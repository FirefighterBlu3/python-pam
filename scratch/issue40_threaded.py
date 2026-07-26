#!/usr/bin/env python3
"""Scratch harness for https://github.com/FirefighterBlu3/python-pam/issues/40

Historically, pam.authenticate() reused a process-global PamAuthenticator and
raced on handle (ArgumentError / segfault under load).

After the fix, --mode shared (module pam.authenticate) should complete cleanly.
--mode fresh (new PamAuthenticator per call) remains the control.

Usage (needs a real local account + PAM):
  python3 scratch/issue40_threaded.py \\
      --username testuser --password 'TestPass123!' \\
      --service python-pam-test --threads 32 --rounds 50 --mode both
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import traceback
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# Prefer in-tree package when run from the repo root.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_PKG = os.path.join(_REPO, "python-pam")
if _PKG not in sys.path:
    sys.path.insert(0, _PKG)

import pam  # noqa: E402
from pam import PamAuthenticator  # noqa: E402


def _worker_shared(username: str, password: str, service: str, rounds: int, stats: Counter, lock: threading.Lock) -> None:
    for _ in range(rounds):
        try:
            pam.authenticate(username, password, service=service)
            with lock:
                stats["ok"] += 1
        except Exception as exc:  # noqa: BLE001 — intentional: catch race exceptions
            key = f"{type(exc).__name__}: {exc}"
            with lock:
                stats["errors"] += 1
                stats[key] += 1
                if stats.get("_tb_saved") is None and "PamHandle" in str(exc):
                    stats["_tb_saved"] = 1
                    stats["_tb"] = traceback.format_exc()


def _worker_fresh(username: str, password: str, service: str, rounds: int, stats: Counter, lock: threading.Lock) -> None:
    for _ in range(rounds):
        try:
            PamAuthenticator().authenticate(username, password, service=service)
            with lock:
                stats["ok"] += 1
        except Exception as exc:  # noqa: BLE001
            key = f"{type(exc).__name__}: {exc}"
            with lock:
                stats["errors"] += 1
                stats[key] += 1


def run(mode: str, username: str, password: str, service: str, threads: int, rounds: int) -> Counter:
    stats: Counter = Counter()
    lock = threading.Lock()
    worker = _worker_shared if mode == "shared" else _worker_fresh
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [
            pool.submit(worker, username, password, service, rounds, stats, lock)
            for _ in range(threads)
        ]
        for fut in as_completed(futures):
            fut.result()
    stats["_elapsed"] = time.perf_counter() - t0
    return stats


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--service", default="login", help="PAM service name (default: login)")
    p.add_argument("--threads", type=int, default=32)
    p.add_argument("--rounds", type=int, default=40, help="Auth attempts per thread")
    p.add_argument(
        "--mode",
        choices=("shared", "fresh", "both"),
        default="both",
        help="shared = pam.authenticate() API; fresh = new PamAuthenticator each call",
    )
    args = p.parse_args()

    modes = ["shared", "fresh"] if args.mode == "both" else [args.mode]
    exit_code = 0

    for mode in modes:
        total = args.threads * args.rounds
        print(f"\n=== mode={mode} threads={args.threads} rounds={args.rounds} total={total} ===")
        print(f"    user={args.username!r} service={args.service!r}")
        stats = run(mode, args.username, args.password, args.service, args.threads, args.rounds)
        elapsed = float(stats.pop("_elapsed", 0.0))
        tb = stats.pop("_tb", None)
        stats.pop("_tb_saved", None)
        ok = stats.pop("ok", 0)
        errors = stats.pop("errors", 0)
        print(f"    ok={ok} errors={errors} elapsed={elapsed:.2f}s")
        if stats:
            print("    exception breakdown:")
            for msg, count in stats.most_common():
                print(f"      {count:5d}  {msg}")
        if tb:
            print("    sample traceback (PamHandle-related):")
            print("\n".join("      " + line for line in str(tb).splitlines()))
        if mode == "shared" and errors:
            exit_code = 1
            if any("PamHandle" in k or "ArgumentError" in k for k in stats):
                print("    >>> reproduced issue #40 style failure")
                exit_code = 2
        elif mode == "fresh" and errors:
            print("    (fresh mode also saw exceptions — may be PAM/config, not only sharing)")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
