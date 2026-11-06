"""
Omni x402 Prover: Production-grade x402 Pay-Per-Proof HTTP + MCP Server for Formal Verification.

Enables autonomous AI agents and protocols to pay USDC micropayments on Base per formal
Z3 / bounded algebraic invariant proof, indexed on Coinbase x402 Bazaar.
"""

from __future__ import annotations

__version__ = "1.0.0"

from omni_x402_prover.x402_protocol import (
    DEFAULT_BASE_PAY_TO,
    DEFAULT_FACILITATOR_URL,
    DeterministicMockFacilitator,
    FacilitatorClient,
    ReplayNonceStore,
    RemoteHTTPFacilitatorClient,
    X402Config,
    build_payment_required_response,
    verify_and_settle_payment,
)
from omni_x402_prover.prover_service import ProverService
from omni_x402_prover.x402_trust_grade import (
    B2B_OFFERS,
    TrustGradeLeaderboard,
    build_seller_fix_pack,
    crawl_x402_directory,
    get_global_leaderboard,
    grade_demo_profile,
    render_leaderboard_html,
    render_trust_grade_svg,
    score_x402_seller,
    validate_public_https_target,
)

__all__ = [
    "__version__",
    "DEFAULT_BASE_PAY_TO",
    "DEFAULT_FACILITATOR_URL",
    "X402Config",
    "ReplayNonceStore",
    "FacilitatorClient",
    "DeterministicMockFacilitator",
    "RemoteHTTPFacilitatorClient",
    "build_payment_required_response",
    "verify_and_settle_payment",
    "ProverService",
    "B2B_OFFERS",
    "TrustGradeLeaderboard",
    "build_seller_fix_pack",
    "crawl_x402_directory",
    "get_global_leaderboard",
    "grade_demo_profile",
    "render_leaderboard_html",
    "render_trust_grade_svg",
    "score_x402_seller",
    "validate_public_https_target",
]
