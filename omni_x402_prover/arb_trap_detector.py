"""
Arb Trap: Polymarket <-> Kalshi Z3 Double-Loss Resolution Divergence Detector.

Formal verification of resolution rule divergence between Polymarket and Kalshi
prediction markets. Detects subtle rule mismatches (timezone cutoffs, official
publication lag, intraday wicks vs daily closes, strict inequality boundaries,
and government shutdown postponement) that cause 100% double-loss wipeouts
(where both legs pay $0.00) in apparent Dutch-book arbitrage trades.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False
    try:
        _parents = Path(__file__).resolve().parents
        if len(_parents) > 2:
            _regalo_venv = _parents[2] / "regalo-asi" / ".venv"
            if _regalo_venv.is_dir():
                for _sp in _regalo_venv.glob("lib/python*/site-packages"):
                    _candidate = str(_sp)
                    if os.path.exists(_candidate) and _candidate not in sys.path:
                        sys.path.append(_candidate)
                        try:
                            import z3
                            _HAS_Z3 = True
                            sys.path.remove(_candidate)
                            break
                        except ImportError:
                            sys.path.remove(_candidate)
    except Exception:
        pass

logger = logging.getLogger("omni_x402_prover.arb_trap")

# Strict Domain Allowlist for Live Market Ingestion
ALLOWED_DOMAINS = {
    "gamma-api.polymarket.com",
    "api.elections.kalshi.com",
}

_MAX_PRICE_BPS = 10_000
_DEFAULT_TIME_WINDOW_SEC = 86400 * 30  # 30 days


@dataclass
class MarketRuleSpec:
    """Normalized resolution rule dimensions for a prediction market."""
    platform: str
    title: str
    rules_text: str
    cutoff_epoch_utc: int
    requires_official_publication: bool
    includes_intraday_wick: bool
    strict_inequality: bool
    numeric_threshold: Optional[int]
    government_shutdown_postpones: bool
    yes_ask: Optional[float] = None
    no_ask: Optional[float] = None
    raw_end_date: Optional[str] = None
    timezone_name: Optional[str] = None


# ---------------------------------------------------------------------------
# 1-Input Live Market Fetchers with Strict Domain Allowlist
# ---------------------------------------------------------------------------

def _validate_allowed_url(url: str) -> None:
    """Enforce strict host allowlist for prediction market API endpoints."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}': must be http or https")
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError(
            f"Host '{parsed.hostname}' not in allowed prediction market domains: {sorted(ALLOWED_DOMAINS)}"
        )


def _default_http_get(url: str, timeout: int = 5) -> str:
    """Deterministic default HTTP GET client with timeout and user agent."""
    _validate_allowed_url(url)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "omni-x402-prover/2.2.0 (Arb-Trap-Detector)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def fetch_polymarket_market(
    slug_or_id: str,
    http_get: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """
    Fetch market metadata from Polymarket Gamma API.
    Injectable http_get enables offline, deterministic unit tests.
    """
    cleaned = str(slug_or_id).strip()
    if not cleaned:
        raise ValueError("Polymarket slug_or_id cannot be empty")

    get_fn = http_get or _default_http_get

    # Check whether slug_or_id is full URL, numeric ID, or text slug
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        url = cleaned
    elif cleaned.isdigit() or (cleaned.startswith("0x") and len(cleaned) > 20):
        url = f"https://gamma-api.polymarket.com/markets/{cleaned}"
    else:
        encoded_slug = urllib.parse.quote(cleaned)
        url = f"https://gamma-api.polymarket.com/markets?slug={encoded_slug}"

    _validate_allowed_url(url)
    raw_json = get_fn(url)
    data = json.loads(raw_json)

    # Polymarket Gamma API returns a list for query params or object for direct ID
    if isinstance(data, list):
        if not data:
            raise ValueError(f"No Polymarket market found for '{cleaned}'")
        item = data[0]
    elif isinstance(data, dict):
        item = data
    else:
        raise ValueError(f"Unexpected Polymarket API response structure for '{cleaned}'")

    title = item.get("question") or item.get("title") or cleaned
    rules_text = (
        item.get("description")
        or item.get("resolutionRules")
        or item.get("rules")
        or ""
    )
    end_date_iso = (
        item.get("endDate")
        or item.get("end_date_iso")
        or item.get("closeTime")
        or ""
    )

    # Best asks extraction
    yes_ask: Optional[float] = None
    no_ask: Optional[float] = None
    outcome_prices = item.get("outcomePrices")
    if outcome_prices:
        if isinstance(outcome_prices, str):
            try:
                outcome_prices = json.loads(outcome_prices)
            except Exception:
                outcome_prices = []
        if isinstance(outcome_prices, list) and len(outcome_prices) >= 2:
            try:
                yes_ask = float(outcome_prices[0])
                no_ask = float(outcome_prices[1])
            except (ValueError, TypeError):
                pass

    if yes_ask is None and "tokens" in item and isinstance(item["tokens"], list):
        tokens = item["tokens"]
        if len(tokens) >= 2:
            yes_ask = float(tokens[0].get("price", 0.5))
            no_ask = float(tokens[1].get("price", 0.5))

    return {
        "platform": "polymarket",
        "slug_or_id": cleaned,
        "title": title,
        "rules_text": rules_text,
        "end_date_iso": end_date_iso,
        "yes_ask": yes_ask,
        "no_ask": no_ask,
        "raw_payload": item,
    }


def fetch_kalshi_market(
    ticker: str,
    http_get: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """
    Fetch market metadata from Kalshi Trade API v2.
    Injectable http_get enables offline, deterministic unit tests.
    """
    cleaned = str(ticker).strip().upper()
    if not cleaned:
        raise ValueError("Kalshi ticker cannot be empty")

    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        url = cleaned
    else:
        url = f"https://api.elections.kalshi.com/trade-api/v2/markets/{urllib.parse.quote(cleaned)}"
    _validate_allowed_url(url)

    get_fn = http_get or _default_http_get
    raw_json = get_fn(url)
    data = json.loads(raw_json)

    market = data.get("market", data) if isinstance(data, dict) else {}
    if not market or not isinstance(market, dict):
        raise ValueError(f"No Kalshi market found for '{cleaned}'")

    title = market.get("title") or market.get("subtitle") or cleaned
    rules_p = market.get("rules_primary") or ""
    rules_s = market.get("rules_secondary") or ""
    rules_text = (f"{rules_p}\n{rules_s}").strip() or market.get("description", "")

    end_date_iso = (
        market.get("close_time")
        or market.get("expiration_time")
        or market.get("expected_expiration_time")
        or ""
    )

    # Kalshi prices are often reported in cents (1..99) or dollars (0.01..0.99)
    raw_yes = market.get("yes_ask") or market.get("yes_price") or market.get("last_price")
    raw_no = market.get("no_ask") or market.get("no_price")
    yes_ask: Optional[float] = None
    no_ask: Optional[float] = None

    if raw_yes is not None:
        val = float(raw_yes)
        yes_ask = val / 100.0 if val > 1.0 else val
    if raw_no is not None:
        val = float(raw_no)
        no_ask = val / 100.0 if val > 1.0 else val

    return {
        "platform": "kalshi",
        "ticker": cleaned,
        "title": title,
        "rules_text": rules_text,
        "end_date_iso": end_date_iso,
        "yes_ask": yes_ask,
        "no_ask": no_ask,
        "raw_payload": market,
    }


# ---------------------------------------------------------------------------
# Rule Spec Normalizer
# ---------------------------------------------------------------------------

def _parse_iso_to_utc_epoch(date_str: str) -> Optional[int]:
    """Parse an ISO 8601 string into UTC timestamp, handling offsets and Z."""
    if not date_str:
        return None
    try:
        clean = date_str.strip()
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return None


def extract_rule_spec(
    title: str,
    rules_text: str,
    end_date_iso: Optional[str] = None,
    platform: str = "generic",
    overrides: Optional[Dict[str, Any]] = None,
) -> MarketRuleSpec:
    """
    Normalize raw market text into deterministic resolution dimensions:
    - cutoff_epoch_utc: int (handling ET/EST/EDT UTC-5/UTC-4 vs UTC cutoffs)
    - requires_official_publication: bool
    - includes_intraday_wick: bool
    - strict_inequality: bool (> X vs >= X)
    - numeric_threshold: Optional[int]
    - government_shutdown_postpones: bool
    """
    combined_text = f"{title} {rules_text}".lower()

    # 1. Cutoff Epoch UTC & Timezone
    cutoff_epoch_utc: Optional[int] = None
    detected_tz: Optional[str] = None

    if end_date_iso:
        cutoff_epoch_utc = _parse_iso_to_utc_epoch(end_date_iso)

    # Detect ET / EST / EDT mentions vs UTC
    has_et = any(k in combined_text for k in [" et", " est", " edt", "eastern time", "new york time", "11:59 pm et", "23:59 et"])
    has_utc = any(k in combined_text for k in [" utc", " gmt", "11:59 pm utc", "23:59 utc"])

    if has_et:
        detected_tz = "EST/EDT"
    elif has_utc:
        detected_tz = "UTC"

    # If rules text explicitly mentions 23:59 ET or 23:59 UTC on a date:
    time_match = re.search(r"(\d{4}-\d{2}-\d{2})[^\w\n]*(?:at|by)?\s*(\d{1,2}:\d{2}(?::\d{2})?)\s*(et|est|edt|utc|gmt)?", combined_text)
    if time_match:
        d_str, t_str, tz_m = time_match.groups()
        try:
            naive_dt = datetime.fromisoformat(f"{d_str}T{t_str}")
            if tz_m in ("et", "est", "edt") or (has_et and not tz_m):
                # Eastern Standard Time is UTC-5
                tz_offset = timezone(timedelta(hours=-5))
                cutoff_epoch_utc = int(naive_dt.replace(tzinfo=tz_offset).timestamp())
                detected_tz = "ET"
            elif tz_m in ("utc", "gmt") or (has_utc and not tz_m):
                cutoff_epoch_utc = int(naive_dt.replace(tzinfo=timezone.utc).timestamp())
                detected_tz = "UTC"
        except Exception:
            pass

    if cutoff_epoch_utc is None:
        # Default fallback epoch: 2025-01-01 00:00:00 UTC
        cutoff_epoch_utc = 1735689600

    # 2. Requires Official Publication
    official_keywords = [
        "federal register",
        "official certification",
        "bls release",
        "bureau of labor statistics",
        "certified results",
        "official publication",
        "official government",
        "fec certification",
        "official agency",
        "cftc rulebook",
    ]
    preliminary_keywords = [
        "media consensus",
        "associated press",
        "ap call",
        "fox news",
        "nbc",
        "cnn",
        "preliminary announcement",
        "preliminary data",
        "tweet",
        "x post",
        "social media",
        "projected winner",
        "initial estimate",
    ]
    has_official = any(k in combined_text for k in official_keywords)
    has_prelim = any(k in combined_text for k in preliminary_keywords)

    if has_official and not has_prelim:
        requires_official_publication = True
    elif has_prelim:
        requires_official_publication = False
    else:
        # Require explicit mention of official sources or government/regulatory agency
        is_gov_agency_market = any(k in combined_text for k in ["bls", "cpi", "fed", "fec", "federal", "gdp", "bureau", "agency", "cftc"])
        requires_official_publication = (platform.lower() == "kalshi" and is_gov_agency_market)

    # 3. Includes Intraday Wick
    wick_keywords = [
        "wick",
        "intraday",
        "touch",
        "touches",
        "hits",
        "hit",
        "at any point",
        "any point before",
        "at any time",
        "reaches",
        "reached",
        "1-minute",
        "high of",
        "low of",
        "intraday high",
    ]
    close_keywords = [
        "daily close",
        "close of trading",
        "settlement price",
        "settlement index",
        "closing price",
        "at 4:00 pm",
        "at 4 pm",
        "market close",
        "settles at close",
    ]
    has_wick = any(k in combined_text for k in wick_keywords)
    has_close = any(k in combined_text for k in close_keywords)

    if has_wick and not has_close:
        includes_intraday_wick = True
    elif has_close:
        includes_intraday_wick = False
    else:
        includes_intraday_wick = (platform.lower() == "polymarket" and "hit" in combined_text)

    # 4. Strict Inequality (> vs >=)
    strict_keywords = [
        "strictly greater",
        "greater than",
        "above",
        "exceeds",
        "more than",
        " > ",
    ]
    greater_equal_keywords = [
        "at least",
        "or higher",
        "or above",
        "or more",
        "greater than or equal",
        " >= ",
        ">=",
        "≥",
    ]
    has_ge = any(k in combined_text for k in greater_equal_keywords)
    has_strict = any(k in combined_text for k in strict_keywords)

    if has_ge:
        strict_inequality = False
    elif has_strict:
        strict_inequality = True
    else:
        strict_inequality = False  # default convention in prediction markets is >=

    # 5. Numeric Threshold
    numeric_threshold: Optional[int] = None
    num_match = re.search(r"(?:>|>=|at least|above|reach|hit)?\s*\$?([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]+)?|\d+)", combined_text)
    if num_match:
        try:
            val_str = num_match.group(1).replace(",", "")
            val_flt = float(val_str)
            if val_flt >= 1000:
                numeric_threshold = int(val_flt)
            elif 0 < val_flt < 100:
                # Scaled basis points / cents
                numeric_threshold = int(round(val_flt * 100))
        except Exception:
            pass

    # 6. Government Shutdown Postponement
    shutdown_postpone_keywords = [
        "shutdown postpones",
        "postponed in the event of government shutdown",
        "delay will extend",
        "delayed release will extend",
        "shutdown delay",
        "extended if government",
        "postponement",
    ]
    shutdown_no_postpone_keywords = [
        "deadline is final",
        "resolves no if not released",
        "shutdown resolves no",
        "no extension",
        "resolve no if delayed",
    ]
    has_postpone = any(k in combined_text for k in shutdown_postpone_keywords)
    has_no_postpone = any(k in combined_text for k in shutdown_no_postpone_keywords)

    if has_postpone:
        government_shutdown_postpones = True
    elif has_no_postpone:
        government_shutdown_postpones = False
    else:
        # Require explicit shutdown mention or government agency context
        is_gov_agency_market = any(k in combined_text for k in ["bls", "cpi", "shutdown", "federal", "bureau", "fec", "gdp"])
        government_shutdown_postpones = (platform.lower() == "kalshi" and is_gov_agency_market)

    spec = MarketRuleSpec(
        platform=platform,
        title=title,
        rules_text=rules_text,
        cutoff_epoch_utc=cutoff_epoch_utc,
        requires_official_publication=requires_official_publication,
        includes_intraday_wick=includes_intraday_wick,
        strict_inequality=strict_inequality,
        numeric_threshold=numeric_threshold,
        government_shutdown_postpones=government_shutdown_postpones,
        raw_end_date=end_date_iso,
        timezone_name=detected_tz,
    )

    # Apply explicit overrides if supplied
    if overrides:
        for k, v in overrides.items():
            if hasattr(spec, k) and v is not None:
                setattr(spec, k, v)

    return spec


# ---------------------------------------------------------------------------
# Z3 Formal Double-Loss Trap Solver
# ---------------------------------------------------------------------------

def _format_epoch(epoch: int, tz_offset_hours: int = 0, suffix: str = "UTC") -> str:
    """Format unix epoch into human readable timestamp."""
    tz = timezone(timedelta(hours=tz_offset_hours))
    dt = datetime.fromtimestamp(epoch, tz=tz)
    return dt.strftime(f"%Y-%m-%d %H:%M:%S {suffix}")


def verify_arb_resolution_divergence(
    pm_spec: MarketRuleSpec,
    kalshi_spec: MarketRuleSpec,
    pm_yes_ask: Optional[float] = None,
    kalshi_no_ask: Optional[float] = None,
    pm_no_ask: Optional[float] = None,
    kalshi_yes_ask: Optional[float] = None,
    fee_bps: int = 0,
) -> Dict[str, Any]:
    """
    Formal Z3 SMT solver proving whether double-loss resolution divergence
    (Outcome_Leg1 == 0 AND Outcome_Leg2 == 0) is SATISFIABLE across real-world event dimensions.

    Checks BOTH arb directions:
    1. BUY_PM_YES_AND_KALSHI_NO: Wipeout occurs if PM_YES is False AND Kalshi_NO is False (Kalshi_YES is True).
    2. BUY_PM_NO_AND_KALSHI_YES: Wipeout occurs if PM_NO is False (PM_YES is True) AND Kalshi_YES is False.
    """
    if not _HAS_Z3:
        raise RuntimeError("z3-solver is required to run formal arb resolution divergence proofs")

    # 1. Compare dimensions to detect syntactic divergence
    divergent_dims: List[str] = []
    if pm_spec.cutoff_epoch_utc != kalshi_spec.cutoff_epoch_utc:
        divergent_dims.append("cutoff_epoch_utc")
    if pm_spec.requires_official_publication != kalshi_spec.requires_official_publication:
        divergent_dims.append("requires_official_publication")
    if pm_spec.includes_intraday_wick != kalshi_spec.includes_intraday_wick:
        divergent_dims.append("includes_intraday_wick")
    if pm_spec.strict_inequality != kalshi_spec.strict_inequality:
        divergent_dims.append("strict_inequality")
    if pm_spec.numeric_threshold != kalshi_spec.numeric_threshold:
        divergent_dims.append("numeric_threshold")
    if pm_spec.government_shutdown_postpones != kalshi_spec.government_shutdown_postpones:
        divergent_dims.append("government_shutdown_postpones")

    # 2. Setup Z3 Symbolic Variables
    event_occurred_epoch = z3.Int("event_occurred_epoch")
    official_pub_epoch = z3.Int("official_pub_epoch")
    intraday_peak = z3.Int("intraday_peak")
    closing_val = z3.Int("closing_val")
    gov_shutdown_delay = z3.Int("gov_shutdown_delay")

    # Bounded physical consistency constraints
    min_cutoff = min(pm_spec.cutoff_epoch_utc, kalshi_spec.cutoff_epoch_utc)
    max_cutoff = max(pm_spec.cutoff_epoch_utc, kalshi_spec.cutoff_epoch_utc)

    base_constraints = [
        event_occurred_epoch > 0,
        official_pub_epoch >= event_occurred_epoch,
        closing_val <= intraday_peak,
        gov_shutdown_delay >= 0,
        event_occurred_epoch >= min_cutoff - 86400 * 7,
        official_pub_epoch <= max_cutoff + 86400 * 30,
        gov_shutdown_delay <= 86400 * 60,
    ]

    base_th = pm_spec.numeric_threshold or kalshi_spec.numeric_threshold or 100_000
    base_constraints.extend([
        closing_val >= 0,
        intraday_peak >= 0,
        closing_val >= max(0, base_th - 50_000),
        intraday_peak <= base_th + 50_000,
    ])

    # For daily-close-only markets, tie peak to close for canonical minimal witnesses
    if not pm_spec.includes_intraday_wick and not kalshi_spec.includes_intraday_wick:
        base_constraints.append(intraday_peak == closing_val)

    # 3. Formulate resolution predicates for PM and Kalshi
    def build_platform_resolution(spec: MarketRuleSpec) -> z3.BoolRef:
        if spec.government_shutdown_postpones:
            effective_cutoff = spec.cutoff_epoch_utc + gov_shutdown_delay
        else:
            effective_cutoff = spec.cutoff_epoch_utc

        if spec.requires_official_publication:
            timing_ok = official_pub_epoch <= effective_cutoff
        else:
            timing_ok = event_occurred_epoch <= effective_cutoff

        if spec.numeric_threshold is not None:
            val = intraday_peak if spec.includes_intraday_wick else closing_val
            if spec.strict_inequality:
                threshold_ok = val > spec.numeric_threshold
            else:
                threshold_ok = val >= spec.numeric_threshold
            return z3.And(timing_ok, threshold_ok)
        else:
            return timing_ok

    pm_yes = build_platform_resolution(pm_spec)
    kalshi_yes = build_platform_resolution(kalshi_spec)

    # 4. Double Loss Wipeout Formulations:
    # Direction 1: BUY PM YES + Kalshi NO
    # Payout is $0 if PM resolves NO AND Kalshi resolves YES
    double_loss_dir1 = z3.And(z3.Not(pm_yes), kalshi_yes)

    # Direction 2: BUY PM NO + Kalshi YES
    # Payout is $0 if PM resolves YES AND Kalshi resolves NO
    double_loss_dir2 = z3.And(pm_yes, z3.Not(kalshi_yes))

    # Solve Direction 1
    s1 = z3.Solver()
    for c in base_constraints:
        s1.add(c)
    s1.add(double_loss_dir1)
    res1 = s1.check()

    # Solve Direction 2
    s2 = z3.Solver()
    for c in base_constraints:
        s2.add(c)
    s2.add(double_loss_dir2)
    res2 = s2.check()

    trap_detected = (res1 == z3.sat) or (res2 == z3.sat)

    # Compute spread and ask pricing
    yes_p = pm_yes_ask if pm_yes_ask is not None else (pm_spec.yes_ask or 0.48)
    no_p = kalshi_no_ask if kalshi_no_ask is not None else (kalshi_spec.no_ask or 0.48)
    sum_asks = yes_p + no_p
    fee = (sum_asks * fee_bps) / 10000.0
    total_cost = sum_asks + fee
    net_spread = max(0.0, 1.0 - total_cost)
    net_spread_bps = int(round(net_spread * 10000))

    if not trap_detected:
        return {
            "status": "SAFE_UNSAT_NO_DOUBLE_LOSS",
            "trap_detected": False,
            "risk_grade": "LOW_RISK",
            "mathematical_guarantee": "UNSAT_NO_DOUBLE_LOSS_IN_MODELED_DIMENSIONS",
            "net_spread_bps": net_spread_bps,
            "max_wipeout_pct": 0.0,
            "divergent_dimensions": divergent_dims,
            "divergent_dimensions_count": len(divergent_dims),
            "witness": None,
            "viral_x_alert": None,
            "message": "Mathematical Guarantee: No double-loss resolution divergence found across modeled dimensions.",
            "details": {
                "pm_spec": asdict(pm_spec),
                "kalshi_spec": asdict(kalshi_spec),
                "solver_direction_1": str(res1),
                "solver_direction_2": str(res2),
            },
        }

    # Select active solver and direction based on user asks if provided
    if (pm_no_ask is not None or kalshi_yes_ask is not None) and res2 == z3.sat:
        active_solver = s2
        active_direction = "BUY_PM_NO_AND_KALSHI_YES"
    elif res1 == z3.sat:
        active_solver = s1
        active_direction = "BUY_PM_YES_AND_KALSHI_NO"
    else:
        active_solver = s2
        active_direction = "BUY_PM_NO_AND_KALSHI_YES"

    model = active_solver.model()

    def _eval_int(var: Any, fallback: int = 0) -> int:
        try:
            val = model.eval(var, model_completion=True)
            return val.as_long()
        except Exception:
            return fallback

    ev_epoch = _eval_int(event_occurred_epoch, min_cutoff)
    pub_epoch = _eval_int(official_pub_epoch, ev_epoch)
    peak_val = _eval_int(intraday_peak, base_th)
    close_val = _eval_int(closing_val, peak_val)
    delay_sec = _eval_int(gov_shutdown_delay, 0)

    ev_utc_str = _format_epoch(ev_epoch, 0, "UTC")
    ev_et_str = _format_epoch(ev_epoch, -5, "EST")
    pub_utc_str = _format_epoch(pub_epoch, 0, "UTC")
    pub_et_str = _format_epoch(pub_epoch, -5, "EST")

    # Generate exact reason explanation
    reasons = []
    divergence_type = "UNKNOWN"
    if pm_spec.cutoff_epoch_utc != kalshi_spec.cutoff_epoch_utc:
        divergence_type = "TIMEZONE_CUTOFF_MISMATCH"
        reasons.append(
            f"Event occurred at {ev_utc_str} ({ev_et_str}), lying between Polymarket cutoff "
            f"({_format_epoch(pm_spec.cutoff_epoch_utc, 0, 'UTC')}) and Kalshi cutoff "
            f"({_format_epoch(kalshi_spec.cutoff_epoch_utc, -5, 'EST')})."
        )
    if pm_spec.strict_inequality != kalshi_spec.strict_inequality and (pm_spec.numeric_threshold or kalshi_spec.numeric_threshold):
        divergence_type = "BOUNDARY_STRICT_INEQUALITY_TRAP"
        reasons.append(
            f"Boundary collision at exact value {peak_val}: Polymarket requires "
            f"{'>' if pm_spec.strict_inequality else '>='} {pm_spec.numeric_threshold} "
            f"while Kalshi requires {'>' if kalshi_spec.strict_inequality else '>='} {kalshi_spec.numeric_threshold}."
        )
    if pm_spec.includes_intraday_wick != kalshi_spec.includes_intraday_wick:
        divergence_type = "INTRADAY_WICK_VS_DAILY_CLOSE"
        reasons.append(
            f"Intraday spike reached {peak_val} (satisfies wick rule), but daily settlement close was "
            f"{close_val} (fails daily close rule)."
        )
    if pm_spec.requires_official_publication != kalshi_spec.requires_official_publication:
        divergence_type = "OFFICIAL_PUBLICATION_LAG"
        reasons.append(
            f"Event/preliminary news occurred at {ev_utc_str}, but official government publication "
            f"lagged until {pub_utc_str} after the contract cutoff."
        )
    if pm_spec.government_shutdown_postpones != kalshi_spec.government_shutdown_postpones and delay_sec > 0:
        divergence_type = "GOVERNMENT_SHUTDOWN_POSTPONEMENT"
        reasons.append(
            f"Government shutdown delayed release by {delay_sec} seconds. Kalshi postpones "
            f"resolution whereas Polymarket resolves NO at scheduled deadline."
        )

    if not reasons:
        reasons.append("Resolution rules diverge between contracts under boundary event conditions.")

    detailed_explanation = " ".join(reasons)
    full_explanation = (
        f"100% DOUBLE-LOSS WIPEOUT: In direction {active_direction}, "
        f"{detailed_explanation} Leg 1 resolves to $0.00 and Leg 2 resolves to $0.00. "
        f"The arbitrageur loses 100% of invested capital despite apparent {net_spread_bps} bps spread."
    )

    witness = {
        "direction": active_direction,
        "divergence_type": divergence_type,
        "event_occurred_epoch": ev_epoch,
        "event_occurred_utc": ev_utc_str,
        "event_occurred_et": ev_et_str,
        "official_pub_epoch": pub_epoch,
        "official_pub_utc": pub_utc_str,
        "official_pub_et": pub_et_str,
        "intraday_peak": peak_val,
        "closing_val": close_val,
        "gov_shutdown_delay_sec": delay_sec,
        "explanation": full_explanation,
        "pm_outcome": {"resolves_yes": (active_direction == "BUY_PM_NO_AND_KALSHI_YES"), "leg_payout": "$0.00"},
        "kalshi_outcome": {"resolves_yes": (active_direction == "BUY_PM_YES_AND_KALSHI_NO"), "leg_payout": "$0.00"},
        "total_arb_payout": "$0.00",
        "wipeout_pct": 100.0,
    }

    # Ready-to-post Viral X / Moltbook Alert
    viral_x_alert = (
        f"🚨 ARB TRAP DETECTED: Polymarket <-> Kalshi 🚨\n"
        f"Pair: {pm_spec.title[:45]} <-> {kalshi_spec.title[:45]}\n"
        f"Apparent Spread: +{net_spread_bps} bps (Dutch-book illusion)\n"
        f"⚠️ 100% DOUBLE-LOSS WIPEOUT RISK ⚠️\n"
        f"Direction: {active_direction}\n"
        f"Why BOTH legs pay $0.00:\n"
        f"- {reasons[0]}\n"
        f"Concrete Z3 Witness: Event at {ev_utc_str} | Price: {peak_val}\n"
        f"Formal Proof: z3-solver SAT divergence witness verified.\n"
        f"Never execute prediction market arbs without checking resolution rules!\n"
        f"#Polymarket #Kalshi #Arbitrage #Z3 #FormalVerification"
    )

    return {
        "status": "VULNERABLE_DOUBLE_LOSS_TRAP",
        "trap_detected": True,
        "risk_grade": "CRITICAL_WIPEOUT_RISK",
        "net_spread_bps": net_spread_bps,
        "max_wipeout_pct": 100.0,
        "divergent_dimensions": divergent_dims,
        "divergent_dimensions_count": len(divergent_dims),
        "witness": witness,
        "viral_x_alert": viral_x_alert,
        "mathematical_guarantee": None,
        "message": f"CRITICAL: Formal Z3 proof found a double-loss resolution divergence ({divergence_type}). Both legs pay $0.00.",
        "details": {
            "pm_spec": asdict(pm_spec),
            "kalshi_spec": asdict(kalshi_spec),
            "solver_direction_1": str(res1),
            "solver_direction_2": str(res2),
        },
    }
