"""Thread isolation and time budgets for Z3 in the prover's request threads.

ThreadingHTTPServer answers every request on its own thread, and the z3 Python
API is not thread-safe on a shared context: ctypes releases the GIL inside each
Z3 call, so threads that share ``z3.main_ctx()`` race in native code.

- The prover's own verifiers build each verification in a private
  ``z3.Context()`` and take their solvers from ``new_solver``.
- The regalo-asi engines only work on the global context, so they run one at a
  time inside ``main_context_lock()``.
- A check that ends ``unknown`` (a timeout included) raises
  ``ProverCapacityError`` with a fixed message. Z3's reason goes to the log,
  never to the client.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Any, Iterator

logger = logging.getLogger("omni_x402_prover.z3_guard")

# The checks in arb_trap_detector and multichain_token_verifier are small linear
# integer problems that Z3 decides in milliseconds.
SOLVER_TIMEOUT_MS = 2_000

# How long a request waits for the regalo-asi engines before answering 503 with
# the payment released. Uncontended, a holder releases within milliseconds.
MAIN_CONTEXT_WAIT_SECONDS = 10.0

UNDECIDED_MESSAGE = "The formal engine could not decide this request within its time budget; retry later"
BUSY_MESSAGE = "The formal engine is busy; retry later"

_main_context_lock = threading.Lock()


class ProverCapacityError(RuntimeError):
    """The engine cannot decide the request within its bounds; never answered with a vacuous proof (HTTP 503)."""


def new_solver(ctx: Any, timeout_ms: int = SOLVER_TIMEOUT_MS) -> Any:
    """Return a solver bound to ``ctx`` whose every check stops after ``timeout_ms``."""
    # The caller already loaded z3, possibly from the regalo-asi venv path it then dropped from sys.path.
    import z3

    solver = z3.Solver(ctx=ctx)
    solver.set("timeout", timeout_ms)
    return solver


def check_decided(solver: Any) -> Any:
    """Return ``solver.check()`` when it is sat or unsat; raise ProverCapacityError when it is unknown."""
    import z3

    result = solver.check()
    if result == z3.unknown:
        logger.warning("Z3 check undecided: %s", solver.reason_unknown())
        raise ProverCapacityError(UNDECIDED_MESSAGE)
    return result


@contextmanager
def main_context_lock(wait_seconds: float = MAIN_CONTEXT_WAIT_SECONDS) -> Iterator[None]:
    """Run the block alone among the engines on ``z3.main_ctx()``; raise ProverCapacityError after ``wait_seconds``."""
    if not _main_context_lock.acquire(timeout=wait_seconds):
        raise ProverCapacityError(BUSY_MESSAGE)
    try:
        yield
    finally:
        _main_context_lock.release()
