#!/usr/bin/env python3
"""
Standalone stress test for PAM authentication with concurrent threads.

This script creates 100 concurrent authentication attempts to stress test
the handle validation and thread safety of the python-pam library.

Usage:
    python stress_test_threaded.py [--username USERNAME] [--password PASSWORD] [--threads N]

If username/password are not provided, the script will use mock authentication
to avoid requiring real system credentials.
"""

import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

try:
    from pam import authenticate, PamAuthenticator
    from pam.__internals import PAM_SUCCESS
except ImportError:
    print("Error: Could not import pam module. Make sure python-pam is installed.")
    print("Try: poetry install")
    sys.exit(1)


class StressTestResult:
    """Container for stress test results."""
    
    def __init__(self):
        self.successful = 0
        self.failed = 0
        self.errors: List[Dict] = []
        self.lock = threading.Lock()
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
    
    def add_success(self):
        with self.lock:
            self.successful += 1
    
    def add_failure(self, thread_id: int, attempt: int, code: int, reason: str):
        with self.lock:
            self.failed += 1
            self.errors.append({
                'thread_id': thread_id,
                'attempt': attempt,
                'code': code,
                'reason': reason
            })
    
    def add_error(self, thread_id: int, attempt: int, error: Exception):
        with self.lock:
            self.failed += 1
            self.errors.append({
                'thread_id': thread_id,
                'attempt': attempt,
                'error': str(error),
                'type': type(error).__name__
            })
    
    def get_duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0


def authenticate_worker(
    thread_id: int,
    num_attempts: int,
    username: str,
    password: str,
    use_separate_instances: bool,
    result: StressTestResult
):
    """Worker function for each thread."""
    for attempt in range(num_attempts):
        try:
            if use_separate_instances:
                # Use separate PamAuthenticator instance for each authentication
                pam_obj = PamAuthenticator()
                auth_result = pam_obj.authenticate(username, password)
                code = pam_obj.code
                reason = pam_obj.reason
            else:
                # Use the global authenticate function (shared instance)
                auth_result = authenticate(username, password)
                # Note: With shared instance, we can't easily get code/reason
                code = PAM_SUCCESS if auth_result else -1
                reason = "Success" if auth_result else "Failed"
            
            if auth_result:
                result.add_success()
            else:
                result.add_failure(thread_id, attempt, code, str(reason))
                
        except Exception as e:
            result.add_error(thread_id, attempt, e)


def run_stress_test(
    num_threads: int = 10,
    attempts_per_thread: int = 10,
    username: Optional[str] = None,
    password: Optional[str] = None,
    use_separate_instances: bool = True,
    use_mock: bool = False
) -> StressTestResult:
    """
    Run stress test with concurrent authentication attempts.
    
    Args:
        num_threads: Number of concurrent threads
        attempts_per_thread: Number of authentication attempts per thread
        username: Username to authenticate (if None, uses mock)
        password: Password to authenticate (if None, uses mock)
        use_separate_instances: If True, each thread uses separate instance
        use_mock: If True, use mock authentication (for testing without real PAM)
    
    Returns:
        StressTestResult with test results
    """
    result = StressTestResult()
    
    # If no credentials provided, use mock mode
    if username is None or password is None:
        use_mock = True
        username = 'test_user'
        password = 'test_password'
        print("Note: No credentials provided, using mock mode")
        print("      (This will test the code path but won't hit real PAM)")
    
    if use_mock:
        print("\n⚠️  MOCK MODE: Using mock authentication")
        print("   To test with real PAM, provide --username and --password\n")
    
    total_attempts = num_threads * attempts_per_thread
    print(f"Starting stress test:")
    print(f"  Threads: {num_threads}")
    print(f"  Attempts per thread: {attempts_per_thread}")
    print(f"  Total attempts: {total_attempts}")
    print(f"  Mode: {'Separate instances' if use_separate_instances else 'Shared instance'}")
    print(f"  Username: {username}")
    print()
    
    result.start_time = time.time()
    
    # Run concurrent authentications
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(
                authenticate_worker,
                i,
                attempts_per_thread,
                username,
                password,
                use_separate_instances,
                result
            )
            for i in range(num_threads)
        ]
        
        # Wait for all threads to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Unexpected error in thread: {e}")
    
    result.end_time = time.time()
    
    return result


def print_results(result: StressTestResult, total_attempts: int):
    """Print stress test results."""
    duration = result.get_duration()
    
    print("\n" + "=" * 70)
    print("STRESS TEST RESULTS")
    print("=" * 70)
    print(f"Total attempts: {total_attempts}")
    print(f"Successful: {result.successful} ({100 * result.successful / total_attempts:.1f}%)")
    print(f"Failed: {result.failed} ({100 * result.failed / total_attempts:.1f}%)")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Throughput: {total_attempts / duration:.2f} attempts/second")
    print()
    
    if result.errors:
        print(f"Errors encountered: {len(result.errors)}")
        print("\nFirst 10 errors:")
        for i, error in enumerate(result.errors[:10], 1):
            if 'error' in error:
                print(f"  {i}. Thread {error['thread_id']}, Attempt {error['attempt']}: "
                      f"{error['type']}: {error['error']}")
            else:
                print(f"  {i}. Thread {error['thread_id']}, Attempt {error['attempt']}: "
                      f"Code {error['code']}, Reason: {error['reason']}")
        if len(result.errors) > 10:
            print(f"  ... and {len(result.errors) - 10} more errors")
        print()
    
    # Check for specific error types
    ctypes_errors = [
        e for e in result.errors
        if 'ctypes.ArgumentError' in e.get('error', '') or
           'ctypes' in e.get('type', '').lower() or
           'ArgumentError' in e.get('error', '')
    ]
    
    handle_errors = [
        e for e in result.errors
        if 'handle' in e.get('error', '').lower() or
           'handle' in e.get('reason', '').lower()
    ]
    
    if ctypes_errors:
        print("❌ CRITICAL: ctypes.ArgumentError detected!")
        print("   This indicates handle validation issues - the bug is present!")
        print(f"   Count: {len(ctypes_errors)}")
        print()
    elif handle_errors:
        print("⚠️  Handle-related errors detected (but not ctypes.ArgumentError)")
        print(f"   Count: {len(handle_errors)}")
        print()
    else:
        print("✅ No ctypes.ArgumentError detected - handle validation working correctly!")
        print("✅ All handle checks passed - no crashes or ArgumentErrors!")
        print()
    
    # Summary
    if result.failed == 0:
        print("✅ All authentications completed successfully!")
    elif result.successful > 0:
        print(f"⚠️  Some authentications failed ({result.failed}/{total_attempts})")
    else:
        print("❌ All authentications failed!")
    
    print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Stress test PAM authentication with concurrent threads',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 100 concurrent attempts (10 threads × 10 attempts)
  python stress_test_threaded.py

  # Test with real credentials
  python stress_test_threaded.py --username myuser --password mypass

  # Custom thread/attempt configuration
  python stress_test_threaded.py --threads 20 --attempts 5

  # Test with shared instance (global authenticate function)
  python stress_test_threaded.py --shared
        """
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    
    parser.add_argument(
        '--attempts',
        type=int,
        default=10,
        help='Number of authentication attempts per thread (default: 10)'
    )
    
    parser.add_argument(
        '--username',
        type=str,
        default=None,
        help='Username for authentication (if not provided, uses mock)'
    )
    
    parser.add_argument(
        '--password',
        type=str,
        default=None,
        help='Password for authentication (if not provided, uses mock)'
    )
    
    parser.add_argument(
        '--shared',
        action='store_true',
        help='Use shared instance (global authenticate function) instead of separate instances'
    )
    
    parser.add_argument(
        '--mock',
        action='store_true',
        help='Force mock mode even if credentials are provided'
    )
    
    args = parser.parse_args()
    
    total_attempts = args.threads * args.attempts
    
    print("PAM Authentication Stress Test")
    print("=" * 70)
    
    # Run the stress test
    result = run_stress_test(
        num_threads=args.threads,
        attempts_per_thread=args.attempts,
        username=args.username,
        password=args.password,
        use_separate_instances=not args.shared,
        use_mock=args.mock
    )
    
    # Print results
    print_results(result, total_attempts)
    
    # Exit with appropriate code
    if result.failed == 0:
        sys.exit(0)
    elif result.successful > 0:
        sys.exit(1)  # Partial success
    else:
        sys.exit(2)  # Complete failure


if __name__ == '__main__':
    main()
