"""
x402 Protocol Implementation for Base USDC Micropayments.

Implements the standard x402 v1 pay-per-resource protocol:
- X402Config: configuration with environment variable loading & strict validation
- ReplayNonceStore: thread-safe, bounded LRU/FIFO store preventing payment replay
- build_payment_required_response: standard HTTP 402 challenge with accepts schema
- FacilitatorClient: Remote HTTP facilitator and Deterministic Mock facilitator
- verify_payment / settle_payment: verification before the paid work, settlement after it
- verify_and_settle_payment: both steps in one call
"""

from __future__ import annotations

import base64
import collections
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Tuple

_ETH_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ALLOWED_NETWORKS: Set[str] = {
    "base",
    "base-mainnet",
    "eip155:8453",
    "base-sepolia",
    "eip155:84532",
}

DEFAULT_BASE_PAY_TO = "0xc8dc4ecb93c4c665Fad07E1261F5f7D60e3C6E0F"
DEFAULT_FACILITATOR_URL = "https://facilitator.payai.network"
COINBASE_CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"
CDP_API_KEY_ID_ENV = "CDP_API_KEY_ID"
CDP_API_KEY_SECRET_ENV = "CDP_API_KEY_SECRET"
CDP_JWT_TTL_SECONDS = 120

logger = logging.getLogger("omni_x402_prover.x402")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_cdp_private_key(api_key_secret: str) -> Tuple[str, Any]:
    """
    Parse a CDP Secret API key the way cdp-sdk does: a PEM EC P-256 key signs ES256,
    a base64 64-byte Ed25519 key (seed + public key) signs EdDSA.
    Raises ImportError without the `cryptography` package and ValueError for any other format.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    secret = api_key_secret.replace("\\n", "\n").strip()
    if secret.startswith("-----BEGIN"):
        key = serialization.load_pem_private_key(secret.encode("utf-8"), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("PEM key is not an EC P-256 private key")
        return "ES256", key
    raw = base64.b64decode(secret)
    if len(raw) != 64:
        raise ValueError("Ed25519 key must decode to 64 bytes")
    return "EdDSA", ed25519.Ed25519PrivateKey.from_private_bytes(raw[:32])


def build_cdp_jwt(
    api_key_id: str,
    alg: str,
    private_key: Any,
    method: str,
    url: str,
) -> str:
    """
    Sign a CDP API JWT bound to one request, with the header and claims of
    cdp-sdk `cdp/auth/utils/jwt.py`: uris = ["<METHOD> <host><path>"], valid for 120 s.
    """
    parsed = urllib.parse.urlparse(url)
    issued_at = int(time.time())
    header = {"alg": alg, "kid": api_key_id, "typ": "JWT", "nonce": f"{secrets.randbelow(10**16):016d}"}
    claims = {
        "sub": api_key_id,
        "iss": "cdp",
        "nbf": issued_at,
        "exp": issued_at + CDP_JWT_TTL_SECONDS,
        "uris": [f"{method.upper()} {parsed.netloc}{parsed.path}"],
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    )
    if alg == "ES256":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        signature = private_key.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{_b64url(signature)}"


def normalize_network_name(network: str) -> str:
    """
    Normalize network names to canonical forms:
    - 'base-mainnet', 'eip155:8453' -> 'base'
    - 'eip155:84532' -> 'base-sepolia'
    - 'base', 'base-sepolia' remain canonical
    """
    cleaned = network.strip().lower()
    if cleaned in ("base", "base-mainnet", "eip155:8453"):
        return "base"
    if cleaned in ("base-sepolia", "eip155:84532"):
        return "base-sepolia"
    return cleaned


def _validate_eth_address(address: str, field_name: str = "address") -> str:
    cleaned = address.strip()
    if not _ETH_ADDRESS_PATTERN.match(cleaned):
        raise ValueError(
            f"Invalid EVM address for {field_name}: '{address}'. Expected 42-char 0x-prefixed hex."
        )
    return cleaned


@dataclass(frozen=True)
class X402Config:
    """Non-custodial configuration for x402 payment settlement on Base."""

    pay_to_address: str = DEFAULT_BASE_PAY_TO
    network: str = "base"
    asset_address: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # Base USDC
    facilitator_url: str = DEFAULT_FACILITATOR_URL
    max_timeout_seconds: int = 60
    price_vault_atomic: int = 20000  # $0.02 USDC (6 decimals)
    price_polymarket_atomic: int = 20000  # $0.02 USDC
    price_zk_bitvec_atomic: int = 30000  # $0.03 USDC
    price_differential_atomic: int = 50000  # $0.05 USDC
    price_forensic_graph_atomic: int = 50000  # $0.05 USDC
    price_blast_radius_atomic: int = 30000  # $0.03 USDC
    price_erc4626_inflation_atomic: int = 30000  # $0.03 USDC
    price_amm_constant_product_atomic: int = 30000  # $0.03 USDC
    price_crosschain_memo_atomic: int = 20000  # $0.02 USDC
    price_cardano_eutxo_atomic: int = 30000  # $0.03 USDC
    price_mev_sandwich_atomic: int = 20000  # $0.02 USDC
    price_permit2_scope_atomic: int = 20000  # $0.02 USDC
    price_liquidation_waterfall_atomic: int = 40000  # $0.04 USDC
    price_merkle_airdrop_atomic: int = 20000  # $0.02 USDC
    price_fiat_crypto_otc_atomic: int = 50000  # $0.05 USDC
    price_sar_ed25519_atomic: int = 50000  # $0.05 USDC

    def __post_init__(self) -> None:
        _validate_eth_address(self.pay_to_address, "pay_to_address")
        _validate_eth_address(self.asset_address, "asset_address")
        if self.network.lower() not in _ALLOWED_NETWORKS:
            raise ValueError(
                f"Unsupported network: '{self.network}'. Allowed: {sorted(_ALLOWED_NETWORKS)}"
            )
        object.__setattr__(self, "network", normalize_network_name(self.network))
        if self.max_timeout_seconds <= 0:
            raise ValueError("max_timeout_seconds must be positive")
        for price_field in (
            "price_vault_atomic",
            "price_polymarket_atomic",
            "price_zk_bitvec_atomic",
            "price_differential_atomic",
            "price_forensic_graph_atomic",
            "price_blast_radius_atomic",
            "price_erc4626_inflation_atomic",
            "price_amm_constant_product_atomic",
            "price_crosschain_memo_atomic",
            "price_cardano_eutxo_atomic",
            "price_mev_sandwich_atomic",
            "price_permit2_scope_atomic",
            "price_liquidation_waterfall_atomic",
            "price_merkle_airdrop_atomic",
            "price_fiat_crypto_otc_atomic",
            "price_sar_ed25519_atomic",
        ):
            val = getattr(self, price_field)
            if not isinstance(val, int) or val <= 0:
                raise ValueError(f"{price_field} must be a positive integer, got {val}")

    @classmethod
    def from_env(cls) -> X402Config:
        """Instantiate config strictly from environment variables with safe defaults."""
        pay_to = os.environ.get("X402_PAY_TO_ADDRESS", "").strip() or DEFAULT_BASE_PAY_TO
        network = os.environ.get("X402_NETWORK", "base").lower()
        asset = os.environ.get("X402_ASSET_ADDRESS", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
        facilitator_url = os.environ.get("X402_FACILITATOR_URL", "").strip() or DEFAULT_FACILITATOR_URL

        try:
            timeout_s = int(os.environ.get("X402_MAX_TIMEOUT_SECONDS", "60"))
        except ValueError:
            timeout_s = 60

        def _env_price(env_key: str, default_val: int) -> int:
            try:
                return int(os.environ.get(env_key, str(default_val)))
            except ValueError:
                return default_val

        p_vault = _env_price("X402_PRICE_VAULT_ATOMIC", 20000)
        p_poly = _env_price("X402_PRICE_POLYMARKET_ATOMIC", 20000)
        p_zk = _env_price("X402_PRICE_ZK_BITVEC_ATOMIC", 30000)
        p_diff = _env_price("X402_PRICE_DIFFERENTIAL_ATOMIC", 50000)
        p_forensic = _env_price("X402_PRICE_FORENSIC_GRAPH_ATOMIC", 50000)
        p_blast = _env_price("X402_PRICE_BLAST_RADIUS_ATOMIC", 30000)
        p_erc4626 = _env_price("X402_PRICE_ERC4626_INFLATION_ATOMIC", 30000)
        p_amm = _env_price("X402_PRICE_AMM_CONSTANT_PRODUCT_ATOMIC", 30000)
        p_memo = _env_price("X402_PRICE_CROSSCHAIN_MEMO_ATOMIC", 20000)
        p_cardano = _env_price("X402_PRICE_CARDANO_EUTXO_ATOMIC", 30000)
        p_mev = _env_price("X402_PRICE_MEV_SANDWICH_ATOMIC", 20000)
        p_permit2 = _env_price("X402_PRICE_PERMIT2_SCOPE_ATOMIC", 20000)
        p_liq = _env_price("X402_PRICE_LIQUIDATION_WATERFALL_ATOMIC", 40000)
        p_merkle = _env_price("X402_PRICE_MERKLE_AIRDROP_ATOMIC", 20000)
        p_otc = _env_price("X402_PRICE_FIAT_CRYPTO_OTC_ATOMIC", 50000)
        p_sar = _env_price("X402_PRICE_SAR_ED25519_ATOMIC", 50000)

        return cls(
            pay_to_address=pay_to,
            network=network,
            asset_address=asset,
            facilitator_url=facilitator_url,
            max_timeout_seconds=timeout_s,
            price_vault_atomic=p_vault,
            price_polymarket_atomic=p_poly,
            price_zk_bitvec_atomic=p_zk,
            price_differential_atomic=p_diff,
            price_forensic_graph_atomic=p_forensic,
            price_blast_radius_atomic=p_blast,
            price_erc4626_inflation_atomic=p_erc4626,
            price_amm_constant_product_atomic=p_amm,
            price_crosschain_memo_atomic=p_memo,
            price_cardano_eutxo_atomic=p_cardano,
            price_mev_sandwich_atomic=p_mev,
            price_permit2_scope_atomic=p_permit2,
            price_liquidation_waterfall_atomic=p_liq,
            price_merkle_airdrop_atomic=p_merkle,
            price_fiat_crypto_otc_atomic=p_otc,
            price_sar_ed25519_atomic=p_sar,
        )


class ReplayNonceStore:
    """
    Thread-safe, bounded in-memory store tracking consumed payment nonces & payload digests.

    Uses an OrderedDict with eviction at max_entries (FIFO/LRU) to protect against memory exhaustion
    while guaranteeing that any previously consumed payment token or nonce cannot be replayed.
    """

    def __init__(self, max_entries: int = 10000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._store: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._in_flight: Set[str] = set()
        self._lock = threading.Lock()

    def reserve(self, *keys: str) -> bool:
        """
        Atomically reserve keys for a payment in flight (verify -> handler -> settle).
        Returns False if any key is already consumed or reserved by a concurrent request.
        """
        live = [key for key in keys if key]
        if not live:
            return False
        with self._lock:
            if any(key in self._store or key in self._in_flight for key in live):
                return False
            self._in_flight.update(live)
            return True

    def release(self, *keys: str) -> None:
        """Drop in-flight reservations so the same payment can be retried after a failed request."""
        with self._lock:
            self._in_flight.difference_update(keys)

    def record(self, key: str) -> bool:
        """
        Atomically check and record a nonce or digest.
        Returns True if newly recorded; False if already consumed (replay).
        """
        if not key:
            return False
        with self._lock:
            if key in self._store:
                return False
            # Evict oldest entry if at capacity
            if len(self._store) >= self._max_entries:
                self._store.popitem(last=False)
            self._store[key] = time.time()
            self._in_flight.discard(key)
            return True

    def is_consumed(self, key: str) -> bool:
        """Check if key has already been consumed."""
        with self._lock:
            return key in self._store

    def size(self) -> int:
        """Current number of tracked nonces."""
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        """Clear all stored nonces (useful in test teardown)."""
        with self._lock:
            self._store.clear()
            self._in_flight.clear()


def build_payment_required_response(
    config: X402Config,
    resource_path: str,
    description: str,
    amount_atomic: int,
    output_schema: Optional[Dict[str, Any]] = None,
    input_schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical x402 v1 402 Payment Required JSON challenge."""
    accepts_item: Dict[str, Any] = {
        "scheme": "exact",
        "network": config.network,
        "maxAmountRequired": str(amount_atomic),
        "resource": resource_path,
        "description": description,
        "mimeType": "application/json",
        "payTo": config.pay_to_address,
        "maxTimeoutSeconds": config.max_timeout_seconds,
        "asset": config.asset_address,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    if output_schema:
        accepts_item["outputSchema"] = output_schema
        accepts_item["discoverable"] = True
    if input_schema:
        accepts_item["inputSchema"] = input_schema

    return {
        "x402Version": 1,
        "error": "X-PAYMENT header is required",
        "accepts": [accepts_item],
    }


def parse_raw_payment_header(raw_header: str) -> Tuple[Dict[str, Any], str]:
    """
    Parse a raw payment header string.

    Supports both Base64-encoded JSON strings and raw JSON strings.
    Returns (decoded_dict, payload_digest_sha256).
    """
    cleaned = raw_header.strip()
    if not cleaned:
        raise ValueError("Empty payment header")

    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()

    # Try Base64 decode first
    decoded_bytes: Optional[bytes] = None
    try:
        decoded_bytes = base64.b64decode(cleaned, validate=True)
    except Exception:
        decoded_bytes = None

    if decoded_bytes:
        try:
            parsed = json.loads(decoded_bytes.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed, digest
        except Exception:
            pass

    # Fallback to direct JSON decode
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed, digest
    except Exception as exc:
        raise ValueError(f"Malformed X-PAYMENT header: not valid Base64 or JSON ({exc})") from exc

    raise ValueError("Malformed X-PAYMENT header: payload is not a JSON object")


class FacilitatorClient:
    """Abstract interface for x402 Facilitator verifier & settler."""

    def verify(
        self, raw_header: str, requirement: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Verify payment authorization validity.
        Returns (is_valid, error_message, verify_details).
        """
        raise NotImplementedError

    def settle(
        self, raw_header: str, requirement: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Settle payment authorization on-chain via facilitator.
        Returns (is_settled, tx_hash, error_message).
        """
        raise NotImplementedError


class RemoteHTTPFacilitatorClient(FacilitatorClient):
    """Production facilitator client communicating via HTTP POST with strict timeout and failover."""

    def __init__(
        self,
        facilitator_url: str,
        timeout_seconds: float = 8.0,
        bearer_token: Optional[str] = None,
        secondary_facilitator_url: Optional[str] = None,
    ) -> None:
        self.facilitator_url = facilitator_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.bearer_token = (
            bearer_token
            if bearer_token is not None
            else os.environ.get("X402_FACILITATOR_BEARER_TOKEN")
        )
        self.secondary_facilitator_url = (
            secondary_facilitator_url
            or os.environ.get("X402_SECONDARY_FACILITATOR_URL")
            or COINBASE_CDP_FACILITATOR_URL
        ).rstrip("/")
        self._cdp_api_key_id = os.environ.get(CDP_API_KEY_ID_ENV, "").strip()
        self._cdp_signing_key: Optional[Tuple[str, Any]] = None
        self._cdp_auth_problem: Optional[str] = None
        cdp_secret = os.environ.get(CDP_API_KEY_SECRET_ENV, "").strip()
        missing = [
            name
            for name, value in ((CDP_API_KEY_ID_ENV, self._cdp_api_key_id), (CDP_API_KEY_SECRET_ENV, cdp_secret))
            if not value
        ]
        if missing:
            self._cdp_auth_problem = f"{' and '.join(missing)} not set"
        else:
            try:
                self._cdp_signing_key = _load_cdp_private_key(cdp_secret)
            except ImportError:
                self._cdp_auth_problem = "the 'cryptography' package is not installed"
            except Exception as exc:
                # Only the exception type: parser messages must never echo key material.
                self._cdp_auth_problem = (
                    f"{CDP_API_KEY_SECRET_ENV} is not a valid CDP Secret API key ({type(exc).__name__})"
                )

    def _headers_for_url(self, target_url: str, method: str = "POST") -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "omni-x402-prover/1.0.0",
        }
        parsed = urllib.parse.urlparse(target_url)
        host = (parsed.hostname or "").lower()
        if self.bearer_token and target_url.startswith(self.facilitator_url):
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif parsed.scheme == "https" and host.endswith(".coinbase.com"):
            if self._cdp_signing_key is not None:
                alg, key = self._cdp_signing_key
                token = build_cdp_jwt(self._cdp_api_key_id, alg, key, method, target_url)
                headers["Authorization"] = f"Bearer {token}"
            else:
                logger.warning(
                    "Sending %s %s without Authorization: %s; Coinbase CDP will reject it with 401",
                    method.upper(),
                    target_url,
                    self._cdp_auth_problem,
                )
        return headers

    def _post_single(self, base_url: str, endpoint: str, data: bytes) -> Dict[str, Any]:
        url = f"{base_url}/{endpoint.lstrip('/')}"
        req = urllib.request.Request(
            url,
            data=data,
            headers=self._headers_for_url(url, "POST"),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_bytes = resp.read()
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as http_err:
            try:
                err_body = http_err.read().decode("utf-8")
                parsed_err = json.loads(err_body)
                msg = (
                    parsed_err.get("invalidMessage")
                    or parsed_err.get("invalidReason")
                    or parsed_err.get("errorMessage")
                    or parsed_err.get("errorReason")
                    or parsed_err.get("error")
                    or parsed_err.get("message")
                    or err_body
                )
            except Exception:
                msg = str(http_err)
            err = RuntimeError(f"Facilitator HTTP {http_err.code}: {msg}")
            setattr(err, "http_code", http_err.code)
            raise err from http_err
        except Exception as exc:
            raise RuntimeError(f"Facilitator connection failure to {url}: {exc}") from exc

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        try:
            return self._post_single(self.facilitator_url, endpoint, data)
        except RuntimeError as primary_err:
            http_code = getattr(primary_err, "http_code", None)
            should_failover = http_code is None or http_code in (429, 500, 502, 503, 504)
            if (
                should_failover
                and self.secondary_facilitator_url
                and self.secondary_facilitator_url != self.facilitator_url
            ):
                try:
                    return self._post_single(self.secondary_facilitator_url, endpoint, data)
                except Exception as secondary_err:
                    logger.warning("Secondary facilitator failed on /%s: %s", endpoint, secondary_err)
            raise primary_err

    def _prepare_payload(
        self, raw_header: str, requirement: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            parsed_payload, _ = parse_raw_payment_header(raw_header)
        except Exception as exc:
            return None, f"Invalid payment header payload: {exc}"

        version = 2 if parsed_payload.get("x402Version") == 2 else 1
        if version == 2:
            req_network = str(requirement.get("network", ""))
            caip_map = {
                "base": "eip155:8453",
                "base-mainnet": "eip155:8453",
                "eip155:8453": "eip155:8453",
                "base-sepolia": "eip155:84532",
                "eip155:84532": "eip155:84532",
            }
            norm_network = caip_map.get(req_network, req_network)
            req_for_facilitator: Dict[str, Any] = {
                "scheme": requirement.get("scheme", "exact"),
                "network": norm_network,
                "amount": str(requirement.get("amount") or requirement.get("maxAmountRequired", "0")),
                "payTo": requirement.get("payTo"),
                "maxTimeoutSeconds": requirement.get("maxTimeoutSeconds", 60),
                "asset": requirement.get("asset"),
                "extra": requirement.get("extra") or {"name": "USD Coin", "version": "2"},
            }
            if "accepted" not in parsed_payload:
                parsed_payload = dict(parsed_payload)
                parsed_payload["accepted"] = req_for_facilitator
        else:
            req_for_facilitator = requirement

        payload = {
            "x402Version": version,
            "paymentPayload": parsed_payload,
            "paymentRequirements": req_for_facilitator,
        }
        return payload, None

    def verify(
        self, raw_header: str, requirement: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        payload, err = self._prepare_payload(raw_header, requirement)
        if err or payload is None:
            return False, err or "Invalid payload", None
        try:
            res = self._post("verify", payload)
            valid = bool(res.get("isValid", res.get("valid", False)))
            if valid:
                return True, None, res
            err_msg = (
                res.get("invalidMessage")
                or res.get("invalidReason")
                or res.get("error")
                or "Payment verification rejected by facilitator"
            )
            return False, str(err_msg), res
        except Exception as exc:
            return False, str(exc), None

    def settle(
        self, raw_header: str, requirement: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        payload, err = self._prepare_payload(raw_header, requirement)
        if err or payload is None:
            return False, None, err or "Invalid payload"
        try:
            res = self._post("settle", payload)
            tx = res.get("transaction") or res.get("txHash") or res.get("tx")
            settled = res.get("success") is True
            if settled and tx:
                return True, str(tx), None
            err_msg = (
                res.get("errorMessage")
                or res.get("errorReason")
                or res.get("error")
                or "Settlement failed at facilitator"
            )
            return False, None, str(err_msg)
        except Exception as exc:
            return False, None, str(exc)


class DeterministicMockFacilitator(FacilitatorClient):
    """
    Deterministic Mock Facilitator for offline development, local CI, and testing.

    Verifies EIP-3009 transferWithAuthorization structure inside x402 payment header:
    - x402Version in (1, 2)
    - scheme == "exact"
    - network matches configured network (supports CAIP-2 aliases)
    - to address matches configured pay_to_address (case-insensitive)
    - value >= required amount
    - validBefore > current_time
    - signature present
    - nonce present
    Returns deterministic 0x hex transaction hash computed from payment header content.
    """

    def __init__(self, config: X402Config) -> None:
        self.config = config

    def _extract_fields(self, raw_header: str) -> Dict[str, Any]:
        parsed, _ = parse_raw_payment_header(raw_header)
        return parsed

    def verify(
        self, raw_header: str, requirement: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        try:
            parsed = self._extract_fields(raw_header)
        except Exception as exc:
            return False, f"Invalid payment header payload: {exc}", None

        # Check x402Version
        version = parsed.get("x402Version")
        if version not in (1, 2):
            return False, f"Unsupported x402Version: {version}. Expected 1 or 2.", None

        # Check scheme
        scheme = parsed.get("scheme") or (parsed.get("accepted") or {}).get("scheme", "")
        if scheme != "exact":
            return False, f"Unsupported payment scheme: '{scheme}'. Expected 'exact'.", None

        # Check network
        network = str(parsed.get("network") or (parsed.get("accepted") or {}).get("network", "")).lower()
        expected_network = self.config.network.lower()
        canonical_network = normalize_network_name(network)
        canonical_expected = normalize_network_name(expected_network)
        caip_aliases = {
            "eip155:8453": "base",
            "base": "eip155:8453",
            "base-mainnet": "base",
            "eip155:84532": "base-sepolia",
            "base-sepolia": "eip155:84532",
        }
        networks_match = (
            network == expected_network
            or canonical_network == canonical_expected
            or caip_aliases.get(network) == expected_network
            or caip_aliases.get(expected_network) == network
            or caip_aliases.get(canonical_network) == canonical_expected
        )
        if not networks_match:
            return (
                False,
                f"Network mismatch: payment on '{network}', resource requires '{expected_network}'.",
                None,
            )

        # Check payload container
        inner_payload = parsed.get("payload")
        if isinstance(inner_payload, dict):
            auth = inner_payload.get("authorization", {})
            sig = inner_payload.get("signature") or parsed.get("signature")
        else:
            auth = parsed.get("authorization", {})
            sig = parsed.get("signature")

        if not isinstance(auth, dict):
            return False, "Missing or invalid 'authorization' structure in payment payload", None

        # Check recipient
        to_addr = str(auth.get("to", "")).strip().lower()
        expected_to = (requirement.get("payTo") or self.config.pay_to_address).strip().lower()
        if to_addr != expected_to:
            return (
                False,
                f"Recipient mismatch: payment sent to '{to_addr}', expected '{expected_to}'.",
                None,
            )

        # Check amount
        try:
            val = int(auth.get("value", 0))
        except (ValueError, TypeError):
            return False, f"Invalid value in payment authorization: {auth.get('value')}", None

        req_amount = int(requirement.get("amount") or requirement.get("maxAmountRequired", 0))
        if val < req_amount:
            return (
                False,
                f"Insufficient payment: provided {val} atomic units, required {req_amount}.",
                None,
            )

        # Check validBefore expiration
        try:
            valid_before = int(auth.get("validBefore", 0))
        except (ValueError, TypeError):
            return False, f"Invalid validBefore timestamp: {auth.get('validBefore')}", None

        now = int(time.time())
        if valid_before <= now:
            return (
                False,
                f"Payment authorization expired: validBefore={valid_before} <= current_time={now}.",
                None,
            )

        # Check non-empty nonce
        nonce = str(auth.get("nonce", "")).strip()
        if not nonce:
            return False, "Missing required 'nonce' in payment authorization", None

        # Check non-empty signature
        sig_str = str(sig or "").strip()
        if not sig_str:
            return False, "Missing required 'signature' in payment payload", None

        payer = auth.get("from", "0x0000000000000000000000000000000000000001")
        details = {
            "payer": payer,
            "recipient": to_addr,
            "value": val,
            "nonce": nonce,
            "validBefore": valid_before,
        }
        return True, None, details

    def settle(
        self, raw_header: str, requirement: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        valid, err, details = self.verify(raw_header, requirement)
        if not valid:
            return False, None, err or "Verification failed prior to settlement"

        # Generate deterministic mock tx hash
        tx_hash = "0x" + hashlib.sha256(f"mock_settle:{raw_header.strip()}".encode("utf-8")).hexdigest()
        return True, tx_hash, None


def verify_payment(
    raw_header: Optional[str],
    requirement: Dict[str, Any],
    config: X402Config,
    nonce_store: ReplayNonceStore,
    facilitator: Optional[FacilitatorClient] = None,
) -> Tuple[bool, int, Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Execute x402 payment verification and replay protection check without settling.

    Returns:
        (is_valid, http_status_code, response_body_dict, verified_payment)
        verified_payment is the input for settle_payment once the paid work has succeeded.
    """
    if not raw_header or not raw_header.strip():
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": "X-PAYMENT header is required",
                "accepts": [requirement],
            },
            None,
        )

    # 1. Parse header and compute payload digest
    try:
        parsed_payload, digest = parse_raw_payment_header(raw_header)
    except Exception as exc:
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": f"Invalid X-PAYMENT header structure: {exc}",
                "accepts": [requirement],
            },
            None,
        )

    # 2. Extract nonce from authorization
    inner = parsed_payload.get("payload")
    if isinstance(inner, dict):
        auth = inner.get("authorization", {})
    else:
        auth = parsed_payload.get("authorization", {})
    nonce = str(auth.get("nonce", "")).strip() if isinstance(auth, dict) else ""

    # 3. Check replay cache before touching facilitator
    # Check payload digest
    if nonce_store.is_consumed(f"digest:{digest}"):
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": "Payment replay rejected: payload has already been consumed",
                "accepts": [requirement],
            },
            None,
        )

    # Check nonce if present
    if nonce and nonce_store.is_consumed(f"nonce:{nonce}"):
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": f"Payment replay rejected: nonce '{nonce}' has already been consumed",
                "accepts": [requirement],
            },
            None,
        )

    # 4. Reserve (digest, nonce) while verify -> handler -> settle is in flight
    in_flight_keys = [f"digest:{digest}"] + ([f"nonce:{nonce}"] if nonce else [])
    if not nonce_store.reserve(*in_flight_keys):
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": "Payment replay rejected: an identical payment is already in flight",
                "accepts": [requirement],
            },
            None,
        )

    # 5. Use facilitator for verification (a raising facilitator must not leak the reservation)
    active_facilitator = facilitator or DeterministicMockFacilitator(config)

    try:
        is_valid, verify_err, verify_details = active_facilitator.verify(raw_header, requirement)
    except Exception as exc:
        is_valid, verify_err, verify_details = False, f"facilitator unavailable ({type(exc).__name__})", None
    if not is_valid:
        nonce_store.release(*in_flight_keys)
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": f"Payment verification failed: {verify_err}",
                "accepts": [requirement],
            },
            None,
        )

    return (
        True,
        200,
        {"success": True},
        {
            "raw_header": raw_header,
            "digest": digest,
            "nonce": nonce,
            "authorization": auth,
            "verify_details": verify_details,
            "facilitator": active_facilitator,
            "in_flight_keys": in_flight_keys,
        },
    )


def release_payment(verified_payment: Optional[Dict[str, Any]], nonce_store: ReplayNonceStore) -> None:
    """Free the in-flight reservation when the paid work failed before settlement (nothing is charged)."""
    if verified_payment:
        nonce_store.release(*verified_payment.get("in_flight_keys", ()))


def settle_payment(
    verified_payment: Dict[str, Any],
    requirement: Dict[str, Any],
    config: X402Config,
    nonce_store: ReplayNonceStore,
) -> Tuple[bool, int, Dict[str, Any], Optional[str]]:
    """
    Settle a payment accepted by verify_payment and atomically record its nonces.

    Returns:
        (is_success, http_status_code, response_body_dict, x_payment_response_b64)
    """
    raw_header = verified_payment["raw_header"]
    digest = verified_payment["digest"]
    nonce = verified_payment["nonce"]
    auth = verified_payment["authorization"]
    verify_details = verified_payment["verify_details"]

    in_flight_keys = list(verified_payment.get("in_flight_keys", ()))

    # 5. Settle
    try:
        is_settled, tx_hash, settle_err = verified_payment["facilitator"].settle(raw_header, requirement)
    except Exception as exc:
        is_settled, tx_hash, settle_err = False, None, f"facilitator unavailable ({type(exc).__name__})"
    if not is_settled or not tx_hash:
        nonce_store.release(*in_flight_keys)
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": f"Payment settlement failed: {settle_err}",
                "accepts": [requirement],
            },
            None,
        )

    # 6. Atomically record consumed nonces in ReplayNonceStore
    recorded_digest = nonce_store.record(f"digest:{digest}")
    if not recorded_digest:
        nonce_store.release(*in_flight_keys)
        return (
            False,
            402,
            {
                "x402Version": 1,
                "error": "Payment replay detected during atomic lock acquisition",
                "accepts": [requirement],
            },
            None,
        )

    if nonce:
        nonce_store.record(f"nonce:{nonce}")

    # 7. Build X-PAYMENT-RESPONSE base64 header
    payer = "unknown"
    if verify_details and isinstance(verify_details, dict):
        payer = str(verify_details.get("payer", payer))
    elif isinstance(auth, dict) and "from" in auth:
        payer = str(auth.get("from"))

    receipt_payload = {
        "success": True,
        "transaction": tx_hash,
        "network": config.network,
        "payer": payer,
    }
    receipt_b64 = base64.b64encode(json.dumps(receipt_payload).encode("utf-8")).decode("utf-8")

    return (
        True,
        200,
        {
            "success": True,
            "settlement": receipt_payload,
        },
        receipt_b64,
    )


def verify_and_settle_payment(
    raw_header: Optional[str],
    requirement: Dict[str, Any],
    config: X402Config,
    nonce_store: ReplayNonceStore,
    facilitator: Optional[FacilitatorClient] = None,
) -> Tuple[bool, int, Dict[str, Any], Optional[str]]:
    """
    Execute full x402 payment verification, replay protection check, and settlement in one step.

    Returns:
        (is_success, http_status_code, response_body_dict, x_payment_response_b64)
    """
    is_valid, status_code, body, verified_payment = verify_payment(
        raw_header, requirement, config, nonce_store, facilitator
    )
    if not is_valid or verified_payment is None:
        return False, status_code, body, None
    return settle_payment(verified_payment, requirement, config, nonce_store)
