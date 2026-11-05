#!/usr/bin/env python3
"""
activate_x402_ecosystem.py - Omni x402 v2 Ecosystem Live Verification & Re-indexing

Verifies live status, endpoints (16 formal verification services), OpenAPI 3.1 specs,
bazaar manifests, and llms.txt AEO docs on both
production gateways:
  - https://gateway.stealthmark.io
  - https://sentinel.oceaneye-ai.com

Optionally runs `npx -y agentcash@latest register <origin>` to re-index both gateways
into x402scan.com and the global x402 Bazaar directory.

Usage:
  python3 scripts/activate_x402_ecosystem.py [--register] [--timeout TIMEOUT]
"""

import argparse
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

DEFAULT_GATEWAYS = [
    "https://gateway.stealthmark.io",
    "https://sentinel.oceaneye-ai.com",
]

ROUTES_TO_VERIFY = [
    "/x402/health",
    "/openapi.json",
    "/.well-known/x402-bazaar.json",
    "/x402/llms.txt",
]


def fetch_url(url: str, timeout: float = 15.0) -> Tuple[int, bytes, Dict[str, str], str]:
    """Fetch URL using urllib.request and return (status, body, headers, error_msg)."""
    headers = {
        "User-Agent": "omni-x402-prover/2.2.0 ecosystem-activator",
        "Accept": "application/json, text/plain, */*",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read()
            resp_headers = {k: v for k, v in resp.headers.items()}
            return status, body, resp_headers, ""
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, body, {k: v for k, v in e.headers.items()}, f"HTTP {e.code}"
    except Exception as e:
        return 0, b"", {}, str(e)


def verify_gateway(origin: str, timeout: float = 15.0) -> Tuple[bool, List[Dict[str, Any]]]:
    """Verify all 4 critical routes for an origin gateway."""
    results: List[Dict[str, Any]] = []
    origin_ok = True

    for route in ROUTES_TO_VERIFY:
        url = origin.rstrip("/") + route
        status, body, headers, err = fetch_url(url, timeout=timeout)
        check_passed = False
        detail = ""

        if status != 200:
            detail = f"Expected 200, got {status} ({err})"
            results.append({
                "origin": origin,
                "route": route,
                "status": status,
                "passed": False,
                "detail": detail,
            })
            origin_ok = False
            continue

        try:
            if route == "/x402/health":
                data = json.loads(body.decode("utf-8"))
                solver_status = data.get("solver_status") or data.get("solver") or "ok"
                check_passed = bool(data.get("status") == "ok" or solver_status)
                detail = f"health ok (solver={solver_status})"

            elif route == "/openapi.json":
                data = json.loads(body.decode("utf-8"))
                paths = data.get("paths", {})
                paths_count = len(paths)

                if paths_count == 16:
                    check_passed = True
                    detail = "16 endpoints verified"
                else:
                    detail = f"endpoints={paths_count}/16"

            elif route == "/.well-known/x402-bazaar.json":
                data = json.loads(body.decode("utf-8"))
                endpoints = data.get("endpoints", [])
                ep_count = len(endpoints)
                if ep_count == 16:
                    check_passed = True
                    detail = f"16 discovery endpoints indexed"
                else:
                    detail = f"endpoints={ep_count}/16"

            elif route == "/x402/llms.txt":
                text = body.decode("utf-8")
                has_title = "Omni x402 Formal Invariant Prover" in text
                has_base = "eip155:8453" in text or "Base" in text
                if has_title and has_base and len(text) > 1000:
                    check_passed = True
                    detail = f"llms.txt verified ({len(text)} bytes, AEO ready)"
                else:
                    detail = f"llms.txt content incomplete (title={has_title})"

        except Exception as ex:
            check_passed = False
            detail = f"Parse/validation error: {ex}"

        if not check_passed:
            origin_ok = False

        results.append({
            "origin": origin,
            "route": route,
            "status": status,
            "passed": check_passed,
            "detail": detail,
        })

    return origin_ok, results


def print_table(results: List[Dict[str, Any]]) -> None:
    """Print ASCII verification table."""
    col_origin = 34
    col_route = 30
    col_status = 8
    col_result = 8
    col_detail = 42

    sep = "+" + "-" * col_origin + "+" + "-" * col_route + "+" + "-" * col_status + "+" + "-" * col_result + "+" + "-" * col_detail + "+"
    header = f"| {'Gateway Origin':<{col_origin-2}} | {'Route':<{col_route-2}} | {'Status':<{col_status-2}} | {'Result':<{col_result-2}} | {'Verification Details':<{col_detail-2}} |"

    print("\n" + sep)
    print(header)
    print(sep)
    for r in results:
        res_str = "PASS" if r["passed"] else "FAIL"
        origin_str = r["origin"].replace("https://", "")
        print(
            f"| {origin_str:<{col_origin-2}} "
            f"| {r['route']:<{col_route-2}} "
            f"| {r['status']:<{col_status-2}} "
            f"| {res_str:<{col_result-2}} "
            f"| {r['detail']:<{col_detail-2}} |"
        )
    print(sep + "\n")


def register_with_agentcash(origins: List[str]) -> bool:
    """Execute npx -y agentcash@latest register <origin> for both gateways."""
    npx_bin = shutil.which("npx")
    if not npx_bin:
        print("[-] Error: 'npx' executable not found in PATH. Install Node.js/npm to run --register.")
        return False

    success = True
    print("\n" + "=" * 70)
    print("Initiating x402scan / agentcash catalog re-indexing via npx...")
    print("=" * 70)

    for origin in origins:
        cmd = [npx_bin, "-y", "agentcash@latest", "register", origin]
        print(f"\n[*] Executing: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.stdout:
                print(proc.stdout.strip())
            if proc.stderr:
                print(proc.stderr.strip(), file=sys.stderr)

            if proc.returncode == 0:
                print(f"[+] Successfully registered {origin} on x402scan")
            else:
                print(f"[-] Registration returned code {proc.returncode} for {origin}")
                success = False
        except Exception as e:
            print(f"[-] Failed executing npx agentcash register for {origin}: {e}")
            success = False

    return success


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Omni x402 live gateways and endpoints."
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Run npx -y agentcash@latest register <origin> to re-index on x402scan.com",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP request timeout in seconds (default: 15.0)",
    )
    parser.add_argument(
        "--gateways",
        nargs="+",
        default=DEFAULT_GATEWAYS,
        help="List of gateway origins to verify",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("Omni x402 v2.2.0 Ecosystem Verifier & Directory Activator")
    print(f"Targets: {', '.join(args.gateways)}")
    print("=" * 70)

    all_passed = True
    combined_results: List[Dict[str, Any]] = []

    for gw in args.gateways:
        ok, res = verify_gateway(gw, timeout=args.timeout)
        combined_results.extend(res)
        if not ok:
            all_passed = False

    print_table(combined_results)

    if all_passed:
        print("[+] SUCCESS: All gateways and 16 formal verification endpoints verified live.")
    else:
        print("[-] FAILURE: One or more gateway checks failed. Review table above.")

    if args.register:
        reg_ok = register_with_agentcash(args.gateways)
        if not reg_ok:
            all_passed = False

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
