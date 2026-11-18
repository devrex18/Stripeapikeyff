# main.py — v7.0.0  (all 25 fixes applied)
import os, re, time, uuid, asyncio, random, threading
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
from typing import Optional, Any

import httpx
import stripe
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware

# ── Pydantic v1 / v2 compat — fix #20 ──────────────────────────
try:
    from pydantic import BaseModel, field_validator, model_validator
    PYDANTIC_V2 = True
except ImportError:
    from pydantic import BaseModel, validator as field_validator
    PYDANTIC_V2 = False

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

VERSION      = "7.0.0"                                          # fix #21
STRIPE_SK    = os.getenv("STRIPE_SK", "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")
API_KEYS     = set(os.getenv("API_KEYS", "mykey123").split(","))
IP_WHITELIST = set(os.getenv("IP_WHITELIST", "").split(",")) - {""}
RATE_LIMIT   = int(os.getenv("RATE_LIMIT", "30"))
BULK_LIMIT   = int(os.getenv("BULK_LIMIT", "20"))

# fix #22 — zero-decimal currencies (amount = units, not cents)
ZERO_DECIMAL_CURRENCIES = {"jpy","krw","vnd","gnf","mga","pyg","rwf","ugx","xaf","xof"}

VALID_CURRENCIES = {
    "usd","eur","gbp","cad","aud","jpy","inr","sgd",
    "chf","hkd","mxn","brl","nok","sek","dkk","pln",
    "krw","vnd","thb","myr","php","idr","czk","ron",
}

# fix #15 — SSRF blocked ranges
BLOCKED_HOSTS = {
    "localhost","127.0.0.1","0.0.0.0","::1",
    "169.254.169.254",   # AWS metadata
    "metadata.google.internal",
    "10.","172.16.","192.168.",
}

app = FastAPI(title="CC Checker API", version=VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════════
# STRIPE — per-request client, no global mutation
# fix #1 #2 #3 #4 #5 #11 #13
# ═══════════════════════════════════════════════════════════════

def get_stripe_client(proxy_url: Optional[str] = None) -> stripe.StripeClient:
    """
    fix #1  — stripe.RequestsClient exists, stripe.HTTPXClient does NOT
    fix #11 — fresh client per request, no shared state
    """
    if proxy_url:
        proxy_dict = {"http": proxy_url, "https": proxy_url}
        http_client = stripe.RequestsClient(proxy=proxy_dict)
        return stripe.StripeClient(api_key=STRIPE_SK, http_client=http_client)
    return stripe.StripeClient(api_key=STRIPE_SK)


async def _stripe_call(fn, *args, **kwargs) -> Any:
    """
    fix #5 — run sync stripe call in thread pool safely
    each call gets its own lambda closure, no shared mutable state
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))


async def stripe_create_pm(
    client: stripe.StripeClient,
    number: str, exp_month: int, exp_year: int, cvc: str,
) -> Any:
    # fix #2 — positional dict, not params= keyword
    return await _stripe_call(
        client.payment_methods.create,
        {
            "type": "card",
            "card": {
                "number":    number,
                "exp_month": exp_month,
                "exp_year":  exp_year,
                "cvc":       cvc,
            },
        },
    )


async def stripe_create_intent(
    client: stripe.StripeClient,
    pm_id: str, amount: int, currency: str,
) -> Any:
    # fix #2 — positional dict
    return await _stripe_call(
        client.payment_intents.create,
        {
            "amount":         amount,
            "currency":       currency,
            "payment_method": pm_id,
            "confirm":        True,
            "automatic_payment_methods": {
                "enabled":        True,
                "allow_redirects": "never",
            },
        },
    )

# ═══════════════════════════════════════════════════════════════
# LRU CACHE WITH TTL — thread-safe
# fix #8 #17
# ═══════════════════════════════════════════════════════════════

class TTLCache:
    def __init__(self, max_size: int = 2000, ttl_seconds: int = 86400):
        self._cache:    OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock:     threading.Lock = threading.Lock()
        self._max_size: int   = max_size
        self._ttl:      float = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            value, ts = self._cache[key]
            if time.time() - ts > self._ttl:
                del self._cache[key]
                return None
            # LRU: move to end
            self._cache.move_to_end(key)
            return value

    def set(self, key: str, value: Any):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (value, time.time())
            # evict oldest if over cap
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)


_bin_cache = TTLCache(max_size=2000, ttl_seconds=86400)   # 24h TTL

# ═══════════════════════════════════════════════════════════════
# PROXY MANAGER
# fix #9 #10 #14 #15 #23
# ═══════════════════════════════════════════════════════════════

class LRUMap:
    """fix #10 — proper LRU eviction"""
    def __init__(self, max_size: int):
        self._data:     OrderedDict[str, str] = OrderedDict()
        self._max_size: int = max_size

    def get(self, key: str) -> Optional[str]:
        if key in self._data:
            self._data.move_to_end(key)
            return self._data[key]
        return None

    def set(self, key: str, value: str):
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = value
        while len(self._data) > self._max_size:
            self._data.popitem(last=False)

    def remove_value(self, value: str):
        keys = [k for k, v in self._data.items() if v == value]
        for k in keys:
            del self._data[k]


class ProxyManager:
    def __init__(self):
        self._pool:     list[str]     = []
        self._lock:     threading.Lock = threading.Lock()   # fix #3 #9
        self._rr_index: int           = 0
        self.mode:      str           = "random"
        self._sticky:   LRUMap        = LRUMap(max_size=10_000)  # fix #10

    def add(self, proxies: list[str]) -> int:
        added = 0
        with self._lock:                                    # fix #9
            for p in proxies:
                p = p.strip()
                if p and p not in self._pool:
                    self._pool.append(p)
                    added += 1
        return added

    def remove(self, proxy: str) -> bool:
        with self._lock:                                    # fix #9
            if proxy in self._pool:
                self._pool.remove(proxy)
                self._sticky.remove_value(proxy)
                return True
        return False

    def clear(self):
        with self._lock:
            self._pool.clear()
            self._sticky = LRUMap(max_size=10_000)
            self._rr_index = 0

    def list_all(self) -> list[str]:
        with self._lock:
            return list(self._pool)

    def get(
        self,
        override:   Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Optional[str]:
        if override:
            return override.strip()
        with self._lock:
            if not self._pool:
                return None
            if self.mode == "roundrobin":
                p = self._pool[self._rr_index % len(self._pool)]
                self._rr_index += 1
                return p
            if self.mode == "sticky" and session_id:
                cached = self._sticky.get(session_id)
                if cached and cached in self._pool:
                    return cached
                chosen = random.choice(self._pool)
                self._sticky.set(session_id, chosen)
                return chosen
            return random.choice(self._pool)

    def _make_client(self, proxy_url: str, timeout: float = 7) -> httpx.AsyncClient:
        # fix #23 — socks5 needs httpx[socks], check gracefully
        try:
            return httpx.AsyncClient(proxy=proxy_url, timeout=timeout)
        except Exception:
            return httpx.AsyncClient(timeout=timeout)

    async def health_check(self) -> dict:
        with self._lock:                                    # fix #9
            snapshot = list(self._pool)

        alive: list[str] = []
        dead:  list[str] = []

        async def test(p: str):
            try:
                async with self._make_client(p) as c:
                    r = await c.get("https://api.ipify.org?format=json")
                    if r.status_code == 200:
                        alive.append(p)
                        return
            except:
                pass
            dead.append(p)

        await asyncio.gather(*[test(p) for p in snapshot])

        with self._lock:                                    # fix #9
            for d in dead:
                if d in self._pool:
                    self._pool.remove(d)

        return {"alive": len(alive), "dead": len(dead), "removed": dead}

    async def test_one(self, proxy: str) -> dict:
        try:
            start = time.time()
            async with self._make_client(proxy, timeout=8) as c:
                r  = await c.get("https://api.ipify.org?format=json")
                ms = int((time.time() - start) * 1000)
                if r.status_code == 200:
                    return {
                        "status": "alive",
                        "ip":     r.json().get("ip"),
                        "ms":     ms,
                        "proxy":  proxy,
                    }
        except Exception as e:
            return {"status": "dead", "error": str(e), "proxy": proxy}
        return {"status": "dead", "proxy": proxy}

    async def import_from_url(self, url: str) -> int:
        # fix #15 — SSRF protection
        url_lower = url.lower()
        for blocked in BLOCKED_HOSTS:
            if blocked in url_lower:
                raise HTTPException(
                    status_code=400,
                    detail=f"BLOCKED URL — internal address not allowed"
                )
        if not url_lower.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r     = await c.get(url)
                lines = r.text.strip().splitlines()
                return self.add(lines)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"import failed: {e}")


proxy_manager = ProxyManager()

# ═══════════════════════════════════════════════════════════════
# RATE LIMITER — per-key AND per-ip
# fix #15 #16
# ═══════════════════════════════════════════════════════════════

_buckets:     dict[str, list[float]] = defaultdict(list)
_bucket_seen: dict[str, float]       = {}
_rl_lock:     threading.Lock         = threading.Lock()
_BUCKET_TTL   = 300.0

def check_rate(identifier: str):
    now    = time.time()
    window = 60.0
    with _rl_lock:
        # fix — evict stale buckets to prevent memory leak
        stale = [k for k, t in _bucket_seen.items() if now - t > _BUCKET_TTL]
        for k in stale:
            _buckets.pop(k, None)
            _bucket_seen.pop(k, None)

        _buckets[identifier]    = [t for t in _buckets[identifier] if now - t < window]
        _bucket_seen[identifier] = now

        if len(_buckets[identifier]) >= RATE_LIMIT:
            reset = int(window - (now - _buckets[identifier][0]))
            raise HTTPException(
                status_code=429,
                detail=f"RATE LIMIT — reset in {reset}s"
            )
        _buckets[identifier].append(now)

# ═══════════════════════════════════════════════════════════════
# AUTH
# fix #16 — per-ip + per-key rate limit
# ═══════════════════════════════════════════════════════════════

def get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else request.client.host

def auth(request: Request, x_api_key: str = Header(...)) -> str:
    ip = get_ip(request)
    if IP_WHITELIST and ip not in IP_WHITELIST:
        raise HTTPException(status_code=403, detail=f"IP {ip} NOT WHITELISTED")
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="INVALID API KEY")
    check_rate(x_api_key)      # per-key
    check_rate(f"ip:{ip}")     # fix #16 — per-ip also
    return x_api_key

# ═══════════════════════════════════════════════════════════════
# CARD UTILITIES
# fix #6 #7 #8 #9 #12 #13
# ═══════════════════════════════════════════════════════════════

def luhn(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def detect_type(number: str) -> str:
    n = number.replace(" ", "")
    patterns = {
        "AMEX":       r"^3[47]",
        "VISA":       r"^4",
        "MASTERCARD": r"^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]))",   # fix #9
        "DISCOVER":   r"^(6011|65|64[4-9])",
        "DINERSCLUB": r"^(30[0-5]|3[68])",
        "JCB":        r"^35(2[89]|[3-8])",
        "UNIONPAY":   r"^62",
        "MAESTRO":    r"^(50|6[0-9])",
    }
    for brand, pat in patterns.items():
        if re.match(pat, n):
            return brand
    return "UNKNOWN"

def validate_expiry(month: int, year: int) -> tuple[bool, str]:
    now = datetime.now()                                    # fix #7 — local not UTC
    y   = year if year >= 100 else 2000 + year             # fix #7 — edge case
    if y < now.year:
        return False, "EXPIRED"
    if y == now.year and month < now.month:
        return False, "EXPIRED"
    if not (1 <= month <= 12):
        return False, "INVALID EXP MONTH"
    return True, "OK"

def flag(alpha2: str) -> str:
    try:                                                    # fix #10
        if not alpha2 or len(alpha2) != 2:
            return ""
        a, b = alpha2.upper()
        if not (a.isalpha() and b.isalpha()):
            return ""
        return (
            chr(0x1F1E6 + ord(a) - ord('A')) +
            chr(0x1F1E6 + ord(b) - ord('A'))
        )
    except:
        return ""

def clean_number(raw: str) -> str:
    # fix #13 — strip ALL non-digits (dots, tabs, dashes, spaces)
    return re.sub(r'\D', '', raw)

def format_card(number: str) -> str:
    # fix #6 — handle 13 / 14 / 15 / 16 / 17 digit cards
    n = number
    l = len(n)
    if l == 15:    return f"{n[:4]} {n[4:10]} {n[10:]}"          # AMEX
    if l == 14:    return f"{n[:4]} {n[4:10]} {n[10:]}"          # Diners
    if l == 13:    return f"{n[:4]} {n[4:9]} {n[9:]}"            # old Visa
    return f"{n[:4]} {n[4:8]} {n[8:12]} {n[12:]}"                # 16+

def normalize_cvc(cvc: str) -> str:
    # fix #12 — strip whitespace from cvc
    return cvc.strip()

def amount_for_currency(amount: int, currency: str) -> int:
    # fix #22 — zero decimal currencies pass amount as-is
    return amount

def amount_display(amount: int, currency: str) -> str:
    cur = currency.lower()
    if cur in ZERO_DECIMAL_CURRENCIES:
        return f"{amount} {cur.upper()}"
    return f"${amount/100:.2f} {cur.upper()}"

# ═══════════════════════════════════════════════════════════════
# BIN LOOKUP — cached, TTL, thread-safe
# fix #6 #17 #19
# ═══════════════════════════════════════════════════════════════

async def bin_lookup(number: str, proxy_url: Optional[str] = None) -> dict:
    bin_code = number[:6]
    empty    = {
        "bin":          bin_code,
        "scheme":       None,
        "type":         None,
        "country":      None,
        "country_code": "",
        "bank":         None,
    }

    # fix #6 #17 — TTLCache is thread-safe
    cached = _bin_cache.get(bin_code)
    if cached is not None:
        return cached

    client_kw: dict = {"timeout": 6}
    if proxy_url:
        try:
            client_kw["proxy"] = proxy_url
        except:
            pass

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(**client_kw) as c:
                r = await c.get(
                    f"https://lookup.binlist.net/{bin_code}",
                    headers={"Accept-Version": "3"},
                )
                if r.status_code == 200:
                    d      = r.json()
                    alpha2 = d.get("country", {}).get("alpha2", "")
                    # fix #19 — scheme fallback chain
                    scheme = (
                        d.get("scheme") or
                        d.get("brand")  or
                        "unknown"
                    )
                    result = {
                        "bin":          bin_code,
                        "scheme":       scheme.upper(),
                        "type":         (d.get("type") or "unknown").upper(),
                        "country":      d.get("country", {}).get("name", None),
                        "country_code": alpha2,
                        "bank":         d.get("bank", {}).get("name", None),
                    }
                    _bin_cache.set(bin_code, result)
                    return result

                if r.status_code == 429 and attempt == 0:
                    await asyncio.sleep(1.5)
                    continue
        except:
            if attempt == 0:
                await asyncio.sleep(0.5)
                continue
        break

    return empty

# ═══════════════════════════════════════════════════════════════
# DECLINE MAP
# ═══════════════════════════════════════════════════════════════

DECLINE_MAP: dict[str, str] = {
    "card_declined":                     "DECLINED",
    "insufficient_funds":                "INSUFFICIENT FUNDS",
    "lost_card":                         "LOST CARD",
    "stolen_card":                       "STOLEN CARD",
    "expired_card":                      "EXPIRED",
    "incorrect_cvc":                     "WRONG CVV",
    "incorrect_number":                  "WRONG NUMBER",
    "invalid_cvc":                       "INVALID CVV",
    "invalid_expiry_month":              "INVALID EXP MONTH",
    "invalid_expiry_year":               "INVALID EXP YEAR",
    "invalid_number":                    "INVALID NUMBER",
    "processing_error":                  "PROCESSING ERROR",
    "do_not_honor":                      "DO NOT HONOR",
    "do_not_try_again":                  "DO NOT RETRY",
    "fraudulent":                        "FLAGGED FRAUD",
    "generic_decline":                   "GENERIC DECLINE",
    "no_action_taken":                   "NO ACTION TAKEN",
    "not_permitted":                     "NOT PERMITTED",
    "restricted_card":                   "RESTRICTED",
    "revocation_of_all_authorizations":  "REVOKED",
    "security_violation":                "SECURITY VIOLATION",
    "service_not_allowed":               "SERVICE NOT ALLOWED",
    "transaction_not_allowed":           "TXN NOT ALLOWED",
    "try_again_later":                   "TRY AGAIN LATER",
    "withdrawal_count_limit_exceeded":   "WITHDRAWAL LIMIT",
    "card_velocity_exceeded":            "VELOCITY EXCEEDED",
    "currency_not_supported":            "CURRENCY UNSUPPORTED",
    "duplicate_transaction":             "DUPLICATE TXN",
    "incorrect_zip":                     "WRONG ZIP",
    "invalid_account":                   "INVALID ACCOUNT",
    "pickup_card":                       "PICKUP CARD",
    "pin_try_exceeded":                  "PIN TRIES EXCEEDED",
    "testmode_decline":                  "TEST DECLINE",
    "bank_cannot_process":               "BANK ERROR",
    "call_issuer":                       "CALL ISSUER",
    "card_not_supported":                "CARD NOT SUPPORTED",
    "authentication_required":           "3DS REQUIRED",
    "new_account_information_available": "ACCOUNT UPDATED",
    "card_not_active":                   "CARD NOT ACTIVE",
    "currency_not_supported":            "CURRENCY NOT SUPPORTED",
}

def map_decline(code: str, msg: str) -> str:
    if code in DECLINE_MAP:
        return DECLINE_MAP[code]
    # fix #19 — clean up raw stripe message, no full sentence
    if msg:
        cleaned = re.sub(r'[.\s]+$', '', msg).upper()
        # strip "YOUR CARD " prefix stripe adds
        cleaned = re.sub(r'^YOUR CARD\s+', '', cleaned)
        return cleaned
    return "UNKNOWN DECLINE"

# ═══════════════════════════════════════════════════════════════
# RESPONSE BUILDER
# fix #24 — request_id in every response
# ═══════════════════════════════════════════════════════════════

def build_response(
    status:      str,
    result:      str,
    number:      str,
    exp_month:   int,
    exp_year:    int,
    cvc:         str,
    bin_data:    dict,
    request_id:  str,
    intent_id:   Optional[str] = None,
    cvc_check:   str           = "unchecked",
    funding:     Optional[str] = None,
    response_ms: int           = 0,
) -> dict:
    alpha2  = bin_data.get("country_code", "")
    country = bin_data.get("country", None)
    fl      = flag(alpha2)

    return {
        "request_id":  request_id,                         # fix #24
        "status":      status,
        "result":      result,
        "card":        format_card(number),
        "exp":         f"{exp_month:02d}/{str(exp_year)[-2:]}",
        "cvv":         cvc,
        "brand":       bin_data.get("scheme", None),
        "funding":     funding,
        "country":     f"{fl} {country}".strip() if country else None,
        "bank":        bin_data.get("bank", None),
        "cvc_check":   cvc_check,
        "intent_id":   intent_id,
        "response_ms": response_ms,
    }

# ═══════════════════════════════════════════════════════════════
# STRIPE ERROR PARSER
# fix #4 — safe attribute access across stripe versions
# ═══════════════════════════════════════════════════════════════

def parse_stripe_card_error(e: stripe.error.CardError) -> tuple[str, str]:
    """returns (code, human_message)"""
    code = ""
    msg  = ""
    try:
        code = getattr(e, "code", "") or ""
        msg  = (
            getattr(e, "user_message", "") or
            getattr(e, "message", "")     or
            ""
        )
        if not code:
            err  = getattr(e, "error", None)
            code = getattr(err, "code", "") or ""
            msg  = msg or getattr(err, "message", "") or ""
    except:
        pass
    return code, msg

# ═══════════════════════════════════════════════════════════════
# CORE CHECKER
# fix #1 #2 #3 #4 #5 #6 #7 #12 #13 #18 #24 #25
# ═══════════════════════════════════════════════════════════════

async def run_check(
    number:     str,
    exp_month:  int,
    exp_year:   int,
    cvc:        str,
    amount:     int           = 100,
    currency:   str           = "usd",
    proxy:      Optional[str] = None,
    session_id: Optional[str] = None,
) -> dict:

    start          = time.time()
    rid            = str(uuid.uuid4())[:8]                  # fix #24
    clean_num      = clean_number(number)                   # fix #13
    cvc            = normalize_cvc(cvc)                     # fix #12
    card_type      = detect_type(clean_num)
    resolved_proxy = proxy_manager.get(proxy, session_id)
    cur            = currency.lower()

    def err(msg: str, bin_data: dict = {}) -> dict:
        return build_response(
            status="ERROR", result=f"⚠️ {msg}",
            number=clean_num, exp_month=exp_month, exp_year=exp_year,
            cvc=cvc, bin_data=bin_data, request_id=rid,
        )

    # ── pre-checks (no stripe hit) ──────────────────────────────
    if not luhn(clean_num):
        return err("INVALID CARD NUMBER (LUHN FAIL)")

    exp_ok, exp_msg = validate_expiry(exp_month, exp_year)
    if not exp_ok:
        return err(exp_msg)

    expected_len = 4 if card_type == "AMEX" else 3
    if len(cvc) != expected_len:
        return err(f"CVV LENGTH WRONG — {card_type} needs {expected_len} digits")

    if cur not in VALID_CURRENCIES:
        return err(f"UNSUPPORTED CURRENCY: {cur.upper()}")

    # fix #22 — zero decimal min is 1, others min is 50
    min_amount = 1 if cur in ZERO_DECIMAL_CURRENCIES else 50
    if amount < min_amount:
        return err(f"AMOUNT TOO LOW — minimum {min_amount} for {cur.upper()}")

    # ── bin lookup ──────────────────────────────────────────────
    bin_data = await bin_lookup(clean_num, resolved_proxy)

    # ── stripe per-request client — fix #1 #11 ─────────────────
    sc = get_stripe_client(resolved_proxy)

    for attempt in range(2):
        try:
            pm_obj = await stripe_create_pm(
                sc, clean_num, exp_month, exp_year, cvc
            )

            intent = await stripe_create_intent(
                sc, pm_obj.id, amount, cur
            )

            # fix #18 — handle all intent statuses
            intent_status = getattr(intent, "status", "")
            if intent_status == "processing":
                ms = int((time.time() - start) * 1000)
                return build_response(
                    status="PROCESSING",
                    result="⏳ PROCESSING — async payment",
                    number=clean_num, exp_month=exp_month, exp_year=exp_year,
                    cvc=cvc, bin_data=bin_data, request_id=rid,
                    intent_id=intent.id, response_ms=ms,
                )
            if intent_status == "canceled":
                ms = int((time.time() - start) * 1000)
                return build_response(
                    status="DECLINED",
                    result="❌ CANCELED",
                    number=clean_num, exp_month=exp_month, exp_year=exp_year,
                    cvc=cvc, bin_data=bin_data, request_id=rid,
                    intent_id=intent.id, response_ms=ms,
                )
            if intent_status == "requires_payment_method":
                ms = int((time.time() - start) * 1000)
                return build_response(
                    status="DECLINED",
                    result="❌ DECLINED",
                    number=clean_num, exp_month=exp_month, exp_year=exp_year,
                    cvc=cvc, bin_data=bin_data, request_id=rid,
                    intent_id=intent.id, response_ms=ms,
                )

            ms        = int((time.time() - start) * 1000)
            cvc_check = "unchecked"
            funding   = None

            # fix #3 — safe attribute access
            try:
                cvc_check = pm_obj.card.checks.cvc_check or "unchecked"
            except:
                pass
            try:
                raw_funding = pm_obj.card.funding
                funding = raw_funding.upper() if raw_funding else None
            except:
                pass

            return build_response(
                status="CHARGED",
                result=f"✅ CHARGED {amount_display(amount, cur)}",
                number=clean_num, exp_month=exp_month, exp_year=exp_year,
                cvc=cvc, bin_data=bin_data, request_id=rid,
                intent_id=intent.id, cvc_check=cvc_check,
                funding=funding, response_ms=ms,
            )

        # fix #4 — correct CardError parsing for all stripe versions
        except stripe.error.CardError as e:
            ms          = int((time.time() - start) * 1000)
            code, msg   = parse_stripe_card_error(e)

            if code == "authentication_required":
                return build_response(
                    status="3DS_REQUIRED", result="🔐 3DS REQUIRED",
                    number=clean_num, exp_month=exp_month, exp_year=exp_year,
                    cvc=cvc, bin_data=bin_data, request_id=rid,
                    cvc_check="unchecked", response_ms=ms,
                )

            return build_response(
                status="DECLINED",
                result=f"❌ {map_decline(code, msg)}",
                number=clean_num, exp_month=exp_month, exp_year=exp_year,
                cvc=cvc, bin_data=bin_data, request_id=rid,
                cvc_check="unchecked", response_ms=ms,
            )

        except stripe.error.InvalidRequestError as e:
            s  = str(e).lower()
            ms = int((time.time() - start) * 1000)
            if   "number" in s: reason = "INVALID CARD NUMBER"
            elif "cvc"    in s: reason = "INVALID CVV"
            elif "expir"  in s: reason = "INVALID EXPIRY"
            elif "amount" in s: reason = "INVALID AMOUNT"
            else:               reason = "INVALID REQUEST"
            return build_response(
                status="ERROR", result=f"⚠️ {reason}",
                number=clean_num, exp_month=exp_month, exp_year=exp_year,
                cvc=cvc, bin_data=bin_data, request_id=rid,
                response_ms=ms,
            )

        # fix #25 — AuthenticationError handled cleanly in bulk too
        except stripe.error.AuthenticationError:
            raise HTTPException(status_code=401, detail="SK KEY INVALID OR REVOKED")

        except stripe.error.RateLimitError:
            if attempt == 0:
                await asyncio.sleep(2)
                continue
            ms = int((time.time() - start) * 1000)
            return build_response(
                status="ERROR", result="⚠️ STRIPE RATE LIMIT",
                number=clean_num, exp_month=exp_month, exp_year=exp_year,
                cvc=cvc, bin_data=bin_data, request_id=rid,
                response_ms=ms,
            )

        except stripe.error.APIConnectionError:
            if attempt == 0:
                await asyncio.sleep(1)
                continue
            ms = int((time.time() - start) * 1000)
            return build_response(
                status="ERROR", result="⚠️ CONNECTION ERROR",
                number=clean_num, exp_month=exp_month, exp_year=exp_year,
                cvc=cvc, bin_data=bin_data, request_id=rid,
                response_ms=ms,
            )

        except Exception as e:
            if attempt == 0:
                await asyncio.sleep(1)
                continue
            ms = int((time.time() - start) * 1000)
            return build_response(
                status="ERROR", result="⚠️ INTERNAL ERROR",
                number=clean_num, exp_month=exp_month, exp_year=exp_year,
                cvc=cvc, bin_data=bin_data, request_id=rid,
                response_ms=ms,
            )

    return build_response(
        status="ERROR", result="⚠️ MAX RETRIES REACHED",
        number=clean_num, exp_month=exp_month, exp_year=exp_year,
        cvc=cvc, bin_data={}, request_id=rid,
    )

# ═══════════════════════════════════════════════════════════════
# MODELS — Pydantic v1/v2 compat
# fix #20
# ═══════════════════════════════════════════════════════════════

class CardPayload(BaseModel):
    number:     str
    exp_month:  int
    exp_year:   int
    cvc:        str
    amount:     int           = 100
    currency:   str           = "usd"
    proxy:      Optional[str] = None
    session_id: Optional[str] = None

    if PYDANTIC_V2:
        @field_validator("amount")
        @classmethod
        def amount_min(cls, v):
            if v < 1:
                raise ValueError("amount must be >= 1")
            return v

        @field_validator("currency")
        @classmethod
        def currency_valid(cls, v):
            if v.lower() not in VALID_CURRENCIES:
                raise ValueError(f"unsupported currency: {v}")
            return v.lower()

        @field_validator("exp_month")
        @classmethod
        def month_valid(cls, v):
            if not (1 <= v <= 12):
                raise ValueError("exp_month must be 1-12")
            return v

        @field_validator("cvc")
        @classmethod
        def cvc_strip(cls, v):
            return v.strip()

        @field_validator("number")
        @classmethod
        def number_clean(cls, v):
            return v.strip()
    else:
        from pydantic import validator as _v

        @_v("amount")
        def amount_min(cls, v):
            if v < 1:
                raise ValueError("amount must be >= 1")
            return v

        @_v("currency")
        def currency_valid(cls, v):
            if v.lower() not in VALID_CURRENCIES:
                raise ValueError(f"unsupported currency: {v}")
            return v.lower()

        @_v("exp_month")
        def month_valid(cls, v):
            if not (1 <= v <= 12):
                raise ValueError("exp_month must be 1-12")
            return v


class BulkPayload(BaseModel):
    cards: list[CardPayload]
    proxy: Optional[str] = None


class ProxyAdd(BaseModel):
    proxies: list[str]


class ProxyRemove(BaseModel):
    proxy: str


class ProxyMode(BaseModel):
    mode: str


class ProxyURL(BaseModel):
    url: str


class ProxyTest(BaseModel):
    proxy: str

# ═══════════════════════════════════════════════════════════════
# ROUTES — CHECKER
# ═══════════════════════════════════════════════════════════════

@app.post("/check")
async def check_card(payload: CardPayload, _: str = Depends(auth)):
    return await run_check(
        number     = payload.number,
        exp_month  = payload.exp_month,
        exp_year   = payload.exp_year,
        cvc        = payload.cvc,
        amount     = payload.amount,
        currency   = payload.currency,
        proxy      = payload.proxy,
        session_id = payload.session_id,
    )


@app.post("/bulk")
async def bulk_check(payload: BulkPayload, _: str = Depends(auth)):
    # fix #14 — empty list check
    if len(payload.cards) == 0:
        raise HTTPException(status_code=400, detail="CARDS LIST EMPTY")
    if len(payload.cards) > BULK_LIMIT:
        raise HTTPException(status_code=400, detail=f"MAX {BULK_LIMIT} CARDS PER BULK")

    tasks = [
        run_check(
            number     = c.number,
            exp_month  = c.exp_month,
            exp_year   = c.exp_year,
            cvc        = c.cvc,
            amount     = c.amount,
            currency   = c.currency,
            proxy      = payload.proxy or c.proxy,
            session_id = c.session_id,
        )
        for c in payload.cards
    ]

    # fix #12 #25 — return_exceptions catches AuthenticationError too
    raw     = await asyncio.gather(*tasks, return_exceptions=True)
    results = []

    for i, r in enumerate(raw):
        if isinstance(r, HTTPException):
            # fix #25 — propagate 401 properly in bulk
            if r.status_code == 401:
                raise r
            c   = payload.cards[i]
            rid = str(uuid.uuid4())[:8]
            results.append(build_response(
                status="ERROR", result=f"⚠️ {r.detail}",
                number=clean_number(c.number),
                exp_month=c.exp_month, exp_year=c.exp_year,
                cvc=normalize_cvc(c.cvc), bin_data={}, request_id=rid,
            ))
        elif isinstance(r, Exception):
            c   = payload.cards[i]
            rid = str(uuid.uuid4())[:8]
            results.append(build_response(
                status="ERROR", result=f"⚠️ {str(r)[:100]}",
                number=clean_number(c.number),
                exp_month=c.exp_month, exp_year=c.exp_year,
                cvc=normalize_cvc(c.cvc), bin_data={}, request_id=rid,
            ))
        else:
            results.append(r)

    charged  = sum(1 for r in results if r["status"] == "CHARGED")
    declined = sum(1 for r in results if r["status"] == "DECLINED")
    tds      = sum(1 for r in results if r["status"] == "3DS_REQUIRED")
    errors   = sum(1 for r in results if r["status"] not in
                   ("CHARGED", "DECLINED", "3DS_REQUIRED"))

    return {
        "total":    len(results),
        "charged":  charged,
        "declined": declined,
        "3ds":      tds,
        "errors":   errors,
        "results":  results,
    }

# ═══════════════════════════════════════════════════════════════
# ROUTES — PROXY
# ═══════════════════════════════════════════════════════════════

@app.post("/proxy/add")
async def proxy_add(payload: ProxyAdd, _: str = Depends(auth)):
    added = proxy_manager.add(payload.proxies)
    return {"added": added, "total": len(proxy_manager.list_all())}


@app.post("/proxy/remove")
async def proxy_remove(payload: ProxyRemove, _: str = Depends(auth)):
    if not proxy_manager.remove(payload.proxy):
        raise HTTPException(status_code=404, detail="proxy not found")
    return {"removed": payload.proxy, "total": len(proxy_manager.list_all())}


@app.get("/proxy/list")
async def proxy_list(_: str = Depends(auth)):
    return {
        "mode":    proxy_manager.mode,
        "total":   len(proxy_manager.list_all()),
        "proxies": proxy_manager.list_all(),
    }


@app.delete("/proxy/clear")
async def proxy_clear(_: str = Depends(auth)):
    proxy_manager.clear()
    return {"status": "pool cleared"}


@app.post("/proxy/mode")
async def proxy_mode(payload: ProxyMode, _: str = Depends(auth)):
    if payload.mode not in ("random", "roundrobin", "sticky"):
        raise HTTPException(
            status_code=400,
            detail="mode must be: random | roundrobin | sticky"
        )
    proxy_manager.mode = payload.mode
    return {"mode": proxy_manager.mode}


@app.post("/proxy/health")
async def proxy_health(_: str = Depends(auth)):
    return await proxy_manager.health_check()


@app.post("/proxy/test")
async def proxy_test(payload: ProxyTest, _: str = Depends(auth)):
    return await proxy_manager.test_one(payload.proxy)


@app.post("/proxy/import")
async def proxy_import(payload: ProxyURL, _: str = Depends(auth)):
    added = await proxy_manager.import_from_url(payload.url)
    return {"imported": added, "total": len(proxy_manager.list_all())}

# ═══════════════════════════════════════════════════════════════
# ROUTES — MISC
# fix #20 — /health behind auth
# ═══════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {"status": "alive", "version": VERSION}         # fix #21


@app.get("/health")
async def health(_: str = Depends(auth)):                  # fix #20
    sk_ok = bool(STRIPE_SK and STRIPE_SK.startswith("sk_"))
    return {
        "api":        "online",
        "version":    VERSION,
        "stripe_key": "set" if sk_ok else "MISSING",
        "proxy_pool": len(proxy_manager.list_all()),
        "proxy_mode": proxy_manager.mode,
        "bin_cached": len(_bin_cache._cache),
    }