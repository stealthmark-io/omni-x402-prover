"""
Offline tests for Z3 thread isolation and solver time budgets (omni_x402_prover.z3_guard).

They need the real z3 engine, so run them with the regalo-asi venv interpreter:
the system python3 falls back without Z3 and skips this module.
"""

from __future__ import annotations

import copy
import functools
import itertools
import json
import sys
import threading
import time
import unittest
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from unittest import mock

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from omni_x402_prover import arb_trap_detector, z3_guard
import omni_x402_prover.prover_service as prover_service_module
from omni_x402_prover.arb_trap_detector import MarketRuleSpec, verify_arb_resolution_divergence
from omni_x402_prover.http_server import create_http_server
from omni_x402_prover.mcp_server import handle_jsonrpc_message
from omni_x402_prover.multichain_token_verifier import LZ_V2_EIDS, verify_multichain_token_invariants
from omni_x402_prover.prover_service import ProverService
from omni_x402_prover.x402_protocol import DeterministicMockFacilitator, ReplayNonceStore, X402Config
from omni_x402_prover.z3_guard import (
    BUSY_MESSAGE,
    SOLVER_TIMEOUT_MS,
    UNDECIDED_MESSAGE,
    ProverCapacityError,
    check_decided,
    main_context_lock,
    new_solver,
)
from tests.test_omni_x402_prover import SAMPLE_PAY_TO, VALID_VAULT_PAYLOAD, http_json_request, make_test_payment_header

# arb_trap_detector imports z3 first, from the regalo-asi venv path when the interpreter lacks it.
HAS_Z3 = bool(getattr(arb_trap_detector, "_HAS_Z3", False))
if HAS_Z3:
    import z3

requires_z3 = unittest.skipUnless(HAS_Z3, "needs the real z3 engine: run with the regalo-asi venv python")

SENTINEL_REASON = "canceled: internal detail 0xdeadbeef"

_E18 = 10**18
_OWNER = "0x9999999999999999999999999999999999999999"
_BASE_ADDR = "0x1111111111111111111111111111111111111111"
_ARB_ADDR = "0x2222222222222222222222222222222222222222"
_OP_ADDR = "0x3333333333333333333333333333333333333333"


def _rule_spec(platform: str, cutoff: int, official: bool = False, threshold: Optional[int] = None) -> MarketRuleSpec:
    return MarketRuleSpec(
        platform=platform,
        title=f"{platform} BTC above 100k",
        rules_text="Resolves YES if BTC is above the threshold at the cutoff.",
        cutoff_epoch_utc=cutoff,
        requires_official_publication=official,
        includes_intraday_wick=False,
        strict_inequality=False,
        numeric_threshold=threshold,
        government_shutdown_postpones=False,
    )


def _arb_trap() -> Dict[str, Any]:
    return verify_arb_resolution_divergence(
        _rule_spec("polymarket", 1735689599),
        _rule_spec("kalshi", 1735707599),
        pm_yes_ask=0.48,
        kalshi_no_ask=0.48,
        fee_bps=100,
    )


def _arb_safe() -> Dict[str, Any]:
    return verify_arb_resolution_divergence(
        _rule_spec("polymarket", 1735689600, official=True, threshold=100000),
        _rule_spec("kalshi", 1735689600, official=True, threshold=100000),
        pm_yes_ask=0.45,
        kalshi_no_ask=0.45,
        fee_bps=50,
    )


def _chain(address: str, total_supply: int, peers: Dict[int, str], **extra: Any) -> Dict[str, Any]:
    chain = {
        "address": address,
        "decimals": 18,
        "shared_decimals": 6,
        "total_supply": total_supply,
        "owner": _OWNER,
        "owner_is_contract": True,
        "has_timelock": True,
        "required_dvns": 2,
        "rate_limit_enabled": True,
        "max_inbound_rate": 500_000 * _E18,
        "peers": peers,
    }
    chain.update(extra)
    return chain


def _safe_chains() -> Dict[str, Any]:
    return {
        "base": _chain(
            _BASE_ADDR, 6_000_000 * _E18, {LZ_V2_EIDS["arbitrum"]: _ARB_ADDR}, locked_supply=4_000_000 * _E18
        ),
        "arbitrum": _chain(_ARB_ADDR, 4_000_000 * _E18, {LZ_V2_EIDS["base"]: _BASE_ADDR}),
    }


def _multichain_safe() -> Dict[str, Any]:
    return verify_multichain_token_invariants(
        {
            "token_address": _BASE_ADDR,
            "home_chain": "base",
            "declared_max_supply": 10_000_000 * _E18,
            "chains": _safe_chains(),
        }
    )


def _multichain_inflated() -> Dict[str, Any]:
    return verify_multichain_token_invariants(
        {
            "token_address": _BASE_ADDR,
            "home_chain": "base",
            "chains": {
                "base": _chain(
                    _BASE_ADDR,
                    10_000_000 * _E18,
                    {LZ_V2_EIDS["arbitrum"]: _ARB_ADDR, LZ_V2_EIDS["optimism"]: _OP_ADDR},
                    locked_supply=1_000_000 * _E18,
                ),
                "arbitrum": _chain(_ARB_ADDR, 800_000 * _E18, {LZ_V2_EIDS["base"]: _BASE_ADDR}),
                "optimism": _chain(_OP_ADDR, 700_000 * _E18, {LZ_V2_EIDS["base"]: _BASE_ADDR}),
            },
        }
    )


VERIFIER_CASES: Dict[str, Callable[[], Dict[str, Any]]] = {
    "arb_trap": _arb_trap,
    "arb_safe": _arb_safe,
    "multichain_safe": _multichain_safe,
    "multichain_inflated": _multichain_inflated,
}

ENGINE_HANDLER_CASES: Tuple[Tuple[str, str, Dict[str, Any]], ...] = (
    ("vault", "verify_vault_and_rounding", VALID_VAULT_PAYLOAD),
    ("basket", "verify_polymarket_basket", {"outcome_ask_prices": [0.48, 0.48]}),
    (
        "bitvec",
        "verify_zk_and_bitvec",
        {"mode": "bitvec", "expr": "a + b", "var_bitwidths": {"a": 8, "b": 8}, "target_bitwidth": 8},
    ),
    (
        "zk",
        "verify_zk_and_bitvec",
        {
            "mode": "zk",
            "public_inputs": ["x"],
            "witness_vars": ["w"],
            "output_var": "w",
            "constraints_exprs": ["w + 1 == x"],
        },
    ),
    (
        "differential",
        "verify_differential_spec",
        {
            "code_a": "def compute(x: int) -> int:\n    return x * 2",
            "code_b": "def compute(x: int) -> int:\n    return x + 1",
            "arg_names": ["x"],
        },
    ),
)

ENGINE_METHODS: Tuple[Tuple[str, str], ...] = (
    ("_prover", "check_vault_share_rounding_conservation"),
    ("_prover", "check_conditional_token_conservation"),
    ("_prover", "check_bitvec_overflow_and_cast_safety"),
    ("_prover", "check_zk_underconstrained_circuit"),
    ("_differential_verifier", "verify_differential_consensus"),
)


def _run_handler(service: ProverService, handler: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return getattr(service, handler)(copy.deepcopy(payload))


@contextmanager
def _undecided_checks(only_call: Optional[int] = None) -> Iterator[None]:
    """Z3 checks end unknown (every one, or only call number ``only_call``) with a reason the client must never see."""
    original_check = z3.Solver.check
    call_numbers = itertools.count()

    def check(solver: Any, *assumptions: Any) -> Any:
        if only_call is None or next(call_numbers) == only_call:
            return z3.unknown
        return original_check(solver, *assumptions)

    with mock.patch.object(z3.Solver, "check", check), mock.patch.object(
        z3.Solver, "reason_unknown", lambda solver: SENTINEL_REASON
    ):
        yield


@contextmanager
def _held_main_context_lock() -> Iterator[None]:
    if not z3_guard._main_context_lock.acquire(timeout=1.0):
        raise AssertionError("the main context lock was already held")
    try:
        yield
    finally:
        z3_guard._main_context_lock.release()


def _short_lock_wait() -> Any:
    return mock.patch.object(
        prover_service_module, "main_context_lock", functools.partial(z3_guard.main_context_lock, wait_seconds=0.05)
    )


class _ImplicitContextSpy:
    """Stands in for z3's global context accessor: records the calling thread, then fails the call."""

    def __init__(self) -> None:
        self.threads: List[str] = []
        self._lock = threading.Lock()

    def __call__(self) -> Any:
        with self._lock:
            self.threads.append(threading.current_thread().name)
        raise AssertionError("implicit use of z3.main_ctx()")

    @contextmanager
    def installed(self) -> Iterator["_ImplicitContextSpy"]:
        with mock.patch.object(z3.z3, "main_ctx", self), mock.patch.object(z3, "main_ctx", self):
            yield self


class _OwnedLock:
    """A threading.Lock that remembers which thread holds it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.owner: Optional[int] = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        acquired = self._lock.acquire(blocking, timeout)
        if acquired:
            self.owner = threading.get_ident()
        return acquired

    def release(self) -> None:
        self.owner = None
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()


def _without_wall_clock(result: Dict[str, Any]) -> Dict[str, Any]:
    """The multichain verdict stamps the second it was computed; everything else is deterministic."""
    return {key: value for key, value in result.items() if key != "timestamp"}


def _assert_expected_verdicts(test: unittest.TestCase, results: Dict[str, Dict[str, Any]]) -> None:
    test.assertEqual(results["arb_trap"]["status"], "VULNERABLE_DOUBLE_LOSS_TRAP")
    test.assertEqual(results["arb_safe"]["status"], "SAFE_UNSAT_NO_DOUBLE_LOSS")
    test.assertEqual(results["multichain_safe"]["status"], "VERIFIED_SAFE")
    test.assertTrue(results["multichain_safe"]["verdict_pass"])
    test.assertEqual(results["multichain_inflated"]["status"], "VERIFICATION_FAILED")
    supply = results["multichain_inflated"]["invariants"]["global_supply_conservation"]
    test.assertEqual(supply["z3_solver_result"], "sat")
    test.assertEqual(supply["unbacked_excess"], 500_000 * _E18)


@requires_z3
class SolverBudgetTests(unittest.TestCase):
    def test_solver_timeout_stops_a_hard_check(self) -> None:
        ctx = z3.Context()
        pigeons, holes = 12, 11
        seat = [[z3.Bool(f"p{p}_h{h}", ctx) for h in range(holes)] for p in range(pigeons)]
        solver = new_solver(ctx, timeout_ms=50)
        for p in range(pigeons):
            solver.add(z3.Or(seat[p]))
        for h in range(holes):
            for a in range(pigeons):
                for b in range(a + 1, pigeons):
                    solver.add(z3.Or(z3.Not(seat[a][h]), z3.Not(seat[b][h])))

        started = time.monotonic()
        with self.assertLogs("omni_x402_prover.z3_guard", "WARNING") as logs:
            with self.assertRaises(ProverCapacityError) as raised:
                check_decided(solver)
        elapsed = time.monotonic() - started

        self.assertEqual(str(raised.exception), UNDECIDED_MESSAGE)
        self.assertLess(elapsed, 2.0)
        self.assertTrue(any("Z3 check undecided:" in line for line in logs.output))

    def test_any_unknown_check_raises_capacity_error_without_internal_detail(self) -> None:
        for name, run in VERIFIER_CASES.items():
            total_checks = sum(1 for kind, _, _ in self._record_solver_calls(run) if kind == "check")
            self.assertGreater(total_checks, 0, name)
            for undecided_call in range(total_checks):
                with self.subTest(case=name, undecided_call=undecided_call):
                    with _undecided_checks(only_call=undecided_call), self.assertLogs(
                        "omni_x402_prover.z3_guard", "WARNING"
                    ) as logs:
                        with self.assertRaises(ProverCapacityError) as raised:
                            run()
                    self.assertEqual(str(raised.exception), UNDECIDED_MESSAGE)
                    self.assertTrue(any(SENTINEL_REASON in line for line in logs.output))

    def test_every_check_runs_under_the_solver_budget(self) -> None:
        for name, run in VERIFIER_CASES.items():
            with self.subTest(case=name):
                events = self._record_solver_calls(run)
                checks = [i for i, (kind, _, _) in enumerate(events) if kind == "check"]
                self.assertTrue(checks, "the verifier never ran a check")
                for i in checks:
                    solver = events[i][1]
                    budgeted = any(
                        kind == "set" and other is solver and args == ("timeout", SOLVER_TIMEOUT_MS)
                        for kind, other, args in events[:i]
                    )
                    self.assertTrue(budgeted, f"check #{i} ran without a {SOLVER_TIMEOUT_MS} ms timeout")

    @staticmethod
    def _record_solver_calls(run: Callable[[], Any]) -> List[Tuple[str, Any, Tuple[Any, ...]]]:
        events: List[Tuple[str, Any, Tuple[Any, ...]]] = []
        original_set = z3.Solver.set
        original_check = z3.Solver.check

        def spy_set(solver: Any, *args: Any, **keys: Any) -> Any:
            events.append(("set", solver, args))
            return original_set(solver, *args, **keys)

        def spy_check(solver: Any, *assumptions: Any) -> Any:
            events.append(("check", solver, assumptions))
            return original_check(solver, *assumptions)

        with mock.patch.object(z3.Solver, "set", spy_set), mock.patch.object(z3.Solver, "check", spy_check):
            run()
        return events


@requires_z3
class ContextIsolationTests(unittest.TestCase):
    def test_concurrent_verifications_use_private_contexts(self) -> None:
        jobs = [name for _ in range(40) for name in VERIFIER_CASES]
        with _ImplicitContextSpy().installed() as spy:
            baseline = {name: run() for name, run in VERIFIER_CASES.items()}
            with ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(lambda name: (name, VERIFIER_CASES[name]()), jobs))

        self.assertEqual(spy.threads, [])
        _assert_expected_verdicts(self, baseline)
        self.assertEqual(len(results), 160)
        for name, result in results:
            self.assertEqual(_without_wall_clock(result), _without_wall_clock(baseline[name]), name)


class MainContextLockTests(unittest.TestCase):
    def test_prover_service_reexports_the_capacity_error(self) -> None:
        self.assertIs(prover_service_module.ProverCapacityError, z3_guard.ProverCapacityError)

    def test_held_lock_answers_busy_after_the_wait(self) -> None:
        with _held_main_context_lock():
            started = time.monotonic()
            with self.assertRaises(ProverCapacityError) as raised:
                with main_context_lock(wait_seconds=0.05):
                    self.fail("entered a held lock")
            elapsed = time.monotonic() - started
        self.assertEqual(str(raised.exception), BUSY_MESSAGE)
        self.assertGreaterEqual(elapsed, 0.04)
        self.assertLess(elapsed, 1.0)

    def test_lock_is_released_when_the_block_raises(self) -> None:
        with self.assertRaises(ValueError):
            with main_context_lock(wait_seconds=0.05):
                raise ValueError("engine failure")
        self.assertFalse(z3_guard._main_context_lock.locked())
        with main_context_lock(wait_seconds=0.05):
            pass

    @requires_z3
    def test_engine_handlers_answer_busy_while_the_lock_is_held(self) -> None:
        service = ProverService(X402Config(pay_to_address=SAMPLE_PAY_TO))
        with _short_lock_wait(), _held_main_context_lock():
            for label, handler, payload in ENGINE_HANDLER_CASES:
                with self.subTest(handler=label):
                    with self.assertRaises(ProverCapacityError) as raised:
                        _run_handler(service, handler, payload)
                    self.assertEqual(str(raised.exception), BUSY_MESSAGE)

    @requires_z3
    def test_concurrent_engine_calls_run_one_at_a_time_under_the_lock(self) -> None:
        service = ProverService(X402Config(pay_to_address=SAMPLE_PAY_TO))
        if not service.is_z3_native:
            self.skipTest("the regalo-asi engines are not loaded")
        baseline = {label: _run_handler(service, handler, payload) for label, handler, payload in ENGINE_HANDLER_CASES}

        owned = _OwnedLock()
        stats_lock = threading.Lock()
        calls: List[Tuple[str, bool]] = []
        active = [0]
        peak = [0]

        def spy(method_name: str, method: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(method)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                with stats_lock:
                    calls.append((method_name, owned.owner == threading.get_ident()))
                    active[0] += 1
                    peak[0] = max(peak[0], active[0])
                try:
                    return method(*args, **kwargs)
                finally:
                    with stats_lock:
                        active[0] -= 1

            return wrapper

        for owner_attr, method_name in ENGINE_METHODS:
            target = getattr(service, owner_attr)
            setattr(target, method_name, spy(method_name, getattr(target, method_name)))

        jobs = [case for _ in range(3) for case in ENGINE_HANDLER_CASES]
        with mock.patch.object(z3_guard, "_main_context_lock", owned):
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda case: (case[0], _run_handler(service, case[1], case[2])), jobs))

        self.assertEqual({name for name, _ in calls}, {name for _, name in ENGINE_METHODS})
        self.assertTrue(all(held for _, held in calls), "an engine ran without holding the lock")
        self.assertEqual(peak[0], 1)
        for label, result in results:
            self.assertEqual(result, baseline[label], label)

    @requires_z3
    def test_busy_engine_mcp_call_is_an_unpaid_error(self) -> None:
        config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        nonce_store = ReplayNonceStore(max_entries=100)
        facilitator = mock.Mock(wraps=DeterministicMockFacilitator(config))
        nonce = "0x" + uuid.uuid4().hex
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "x402_verify_vault_rounding",
                "arguments": {
                    **VALID_VAULT_PAYLOAD,
                    "paymentHeader": make_test_payment_header(config, amount=20000, nonce=nonce),
                },
            },
        }
        with _short_lock_wait(), _held_main_context_lock():
            response = handle_jsonrpc_message(
                req=request,
                config=config,
                prover_service=ProverService(config),
                nonce_store=nonce_store,
                facilitator=facilitator,
            )

        result = response["result"]
        self.assertTrue(result["isError"])
        self.assertIn(BUSY_MESSAGE, result["content"][0]["text"])
        self.assertNotIn("settlement", result.get("_meta", {}))
        self.assertFalse(nonce_store.is_consumed(f"nonce:{nonce}"))
        facilitator.settle.assert_not_called()


@requires_z3
class CapacityOverHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = X402Config(pay_to_address=SAMPLE_PAY_TO)
        self.nonce_store = ReplayNonceStore(max_entries=1000)
        self.facilitator = mock.Mock(wraps=DeterministicMockFacilitator(self.config))
        self.server = create_http_server(
            host="127.0.0.1",
            port=0,
            config=self.config,
            prover_service=ProverService(self.config),
            nonce_store=self.nonce_store,
            facilitator=self.facilitator,
        )
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)

    def _assert_unpaid(self, body: Dict[str, Any], headers: Dict[str, str]) -> None:
        self.assertNotIn("x-payment-response", {k.lower() for k in headers})
        self.assertNotIn("settlementReceipt", body)
        self.assertEqual(self.nonce_store.size(), 0)
        self.facilitator.settle.assert_not_called()

    def test_busy_engine_answers_503_and_releases_the_payment(self) -> None:
        header = make_test_payment_header(self.config, amount=20000)
        with _short_lock_wait(), _held_main_context_lock():
            status, body, headers = http_json_request(
                self.base_url,
                "POST",
                "/x402/verify-vault-and-rounding",
                data=VALID_VAULT_PAYLOAD,
                headers={"X-PAYMENT": header},
            )
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": BUSY_MESSAGE})
        self._assert_unpaid(body, headers)

    def test_undecided_check_answers_503_without_internal_detail(self) -> None:
        header = make_test_payment_header(self.config, amount=20000)
        payload = {
            "token_address": _BASE_ADDR,
            "chain": "base",
            "declared_max_supply": 10_000_000 * _E18,
            "chains_config": _safe_chains(),
        }
        with _undecided_checks(), self.assertLogs("omni_x402_prover.z3_guard", "WARNING") as logs:
            status, body, headers = http_json_request(
                self.base_url,
                "POST",
                "/x402/verify-bridge-and-oracle",
                data=payload,
                headers={"X-PAYMENT": header},
            )
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": UNDECIDED_MESSAGE})
        self.assertNotIn(SENTINEL_REASON, json.dumps(body))
        self.assertTrue(any(SENTINEL_REASON in line for line in logs.output))
        self._assert_unpaid(body, headers)

    def test_undecided_arb_preview_fails_without_internal_detail(self) -> None:
        query = urllib.parse.urlencode(
            {
                "pm_rules": "Resolves YES if BTC trades above 100000 at any time before the cutoff.",
                "kalshi_rules": "Resolves YES if BTC closes above 100000 on the cutoff date.",
            }
        )
        with _undecided_checks(), self.assertLogs("omni_x402_prover.z3_guard", "WARNING"):
            status, body, _ = http_json_request(self.base_url, "GET", f"/x402/arb-trap/preview?{query}")
        self.assertGreaterEqual(status, 500)
        self.assertNotIn(SENTINEL_REASON, json.dumps(body))
        self.assertNotIn("mathematical_guarantee", body)
        self.assertNotIn("trap_detected", body)


if __name__ == "__main__":
    unittest.main()
