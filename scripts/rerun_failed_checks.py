#!/usr/bin/env python3
"""
Script to check for failed required checks on a GitHub PR and re-run them.
This is useful for handling flaky e2e tests.

Usage:
    # One-time check and retry
    python scripts/rerun_failed_checks.py --pr 347
    
    # Continuous monitoring with auto-retry
    python scripts/rerun_failed_checks.py --pr 347 --watch
    
    # Watch with custom check interval
    python scripts/rerun_failed_checks.py --pr 347 --watch --interval 60

Requirements:
    pip install requests
"""

import argparse
import os
import sys
import time
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional
import requests


def log(message: str) -> None:
    """Print a message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


def check_gh_auth() -> bool:
    """Check if gh CLI is authenticated."""
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=5
        )
        # gh auth status returns 0 if authenticated
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def gh_api_call(endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Make an API call using gh CLI."""
    try:
        cmd = ["gh", "api", endpoint, "-X", method]
        if data:
            import json
            cmd.extend(["--input", "-"])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=json.dumps(data) if data else None,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout:
            import json
            return json.loads(result.stdout)
        return None
    except Exception:
        return None


class PRCheckRerunner:
    def __init__(self, token: Optional[str], repo: str = "kubefleet-dev/kubefleet", use_gh_cli: bool = False):
        """Initialize the PR check re-runner."""
        self.repo_name = repo
        self.token = token
        self.use_gh_cli = use_gh_cli
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        } if token else {}
        self.base_url = "https://api.github.com"
    
    def get_pr_info(self, pr_number: int) -> Dict[str, Any]:
        """Get PR information."""
        if self.use_gh_cli:
            result = gh_api_call(f"/repos/{self.repo_name}/pulls/{pr_number}")
            if result:
                return result
        
        url = f"{self.base_url}/repos/{self.repo_name}/pulls/{pr_number}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def get_pr_checks(self, pr_number: int) -> List[Dict[str, Any]]:
        """Get all check runs for a PR."""
        pr_info = self.get_pr_info(pr_number)
        head_sha = pr_info["head"]["sha"]
        
        # Get check runs for the head commit
        if self.use_gh_cli:
            result = gh_api_call(f"/repos/{self.repo_name}/commits/{head_sha}/check-runs")
            if result:
                return result.get("check_runs", [])
        
        url = f"{self.base_url}/repos/{self.repo_name}/commits/{head_sha}/check-runs"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        
        return response.json().get("check_runs", [])
    
    def get_failed_checks(self, pr_number: int) -> List[Dict[str, Any]]:
        """Get all failed check runs for a PR."""
        checks = self.get_pr_checks(pr_number)
        failed_checks = [
            check for check in checks
            if check.get("conclusion") in ["failure", "timed_out", "cancelled"]
            and check.get("status") == "completed"
        ]
        return failed_checks
    
    def get_in_progress_checks(self, pr_number: int) -> List[Dict[str, Any]]:
        """Get all in-progress check runs for a PR."""
        checks = self.get_pr_checks(pr_number)
        in_progress = [
            check for check in checks
            if check.get("status") in ["queued", "in_progress"]
        ]
        return in_progress
    
    def get_e2e_failed_checks(self, pr_number: int) -> List[Dict[str, Any]]:
        """Get all failed e2e check runs for a PR."""
        failed_checks = self.get_failed_checks(pr_number)
        e2e_checks = [
            check for check in failed_checks
            if "e2e" in check.get("name", "").lower() or "test" in check.get("name", "").lower()
        ]
        return e2e_checks
    
    def rerun_check(self, check_run_id: int) -> bool:
        """Re-run a specific check run."""
        if self.use_gh_cli:
            result = gh_api_call(f"/repos/{self.repo_name}/check-runs/{check_run_id}/rerequest", method="POST")
            if result is not None:
                return True
            print(f"  ⚠️  Could not re-run check {check_run_id} via gh CLI")
            return False
        
        url = f"{self.base_url}/repos/{self.repo_name}/check-runs/{check_run_id}/rerequest"
        
        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status()
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(f"  ⚠️  Permission denied to re-run check {check_run_id}")
                return False
            elif e.response.status_code == 404:
                print(f"  ⚠️  Check run {check_run_id} not found")
                return False
            else:
                print(f"  ❌ Error re-running check {check_run_id}: {e}")
                return False
    
    def rerun_failed_workflow(self, workflow_run_id: int) -> bool:
        """Re-run a failed workflow run."""
        if self.use_gh_cli:
            result = gh_api_call(f"/repos/{self.repo_name}/actions/runs/{workflow_run_id}/rerun-failed-jobs", method="POST")
            if result is not None:
                return True
            print(f"  ❌ Error re-running workflow {workflow_run_id} via gh CLI")
            return False
        
        url = f"{self.base_url}/repos/{self.repo_name}/actions/runs/{workflow_run_id}/rerun-failed-jobs"
        
        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status()
            return True
        except requests.exceptions.HTTPError as e:
            print(f"  ❌ Error re-running workflow {workflow_run_id}: {e}")
            return False
    
    def get_workflow_runs_for_pr(self, pr_number: int) -> List[Dict[str, Any]]:
        """Get workflow runs associated with a PR."""
        pr_info = self.get_pr_info(pr_number)
        head_sha = pr_info["head"]["sha"]
        
        if self.use_gh_cli:
            result = gh_api_call(f"/repos/{self.repo_name}/actions/runs?head_sha={head_sha}")
            if result:
                return result.get("workflow_runs", [])
        
        url = f"{self.base_url}/repos/{self.repo_name}/actions/runs"
        params = {"head_sha": head_sha}
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        
        return response.json().get("workflow_runs", [])
    
    def get_failed_workflow_runs(self, pr_number: int) -> List[Dict[str, Any]]:
        """Get failed workflow runs for a PR."""
        workflow_runs = self.get_workflow_runs_for_pr(pr_number)
        failed_runs = [
            run for run in workflow_runs
            if run.get("conclusion") in ["failure", "timed_out", "cancelled"]
            and run.get("status") == "completed"
        ]
        return failed_runs
    
    def process_pr(self, pr_number: int, dry_run: bool = False, filter_e2e: bool = True) -> None:
        """Process a PR and re-run failed checks."""
        log(f"🔍 Checking PR #{pr_number}...")
        
        # Get PR info
        pr_info = self.get_pr_info(pr_number)
        log(f"PR Title: {pr_info['title']}")
        log(f"PR State: {pr_info['state']}")
        log(f"Head SHA: {pr_info['head']['sha']}")
        
        # Check for in-progress checks
        in_progress_checks = self.get_in_progress_checks(pr_number)
        if in_progress_checks:
            log(f"⏳ Found {len(in_progress_checks)} checks still in progress:")
            for check in in_progress_checks:
                log(f"  ⏳ {check.get('name')} - {check.get('status')}")
            log("⚠️  Cannot re-run checks while some are still in progress.")
            log("Please wait for all checks to complete before re-running.")
            return
        
        # Get failed checks
        if filter_e2e:
            failed_checks = self.get_e2e_failed_checks(pr_number)
            log(f"Found {len(failed_checks)} failed e2e/test checks")
        else:
            failed_checks = self.get_failed_checks(pr_number)
            log(f"Found {len(failed_checks)} failed checks")
        
        if not failed_checks:
            log("✅ No failed checks to re-run!")
            return
        
        log("Failed checks:")
        for check in failed_checks:
            status_icon = "❌" if check.get("conclusion") == "failure" else "⏱️"
            log(f"  {status_icon} {check.get('name')} - {check.get('conclusion')}")
        
        # Try re-running via check runs first
        if not dry_run:
            log("🔄 Re-running failed checks via check-runs API...")
            success_count = 0
            for check in failed_checks:
                check_id = check.get("id")
                check_name = check.get("name")
                log(f"  Re-running: {check_name} (ID: {check_id})")
                
                if self.rerun_check(check_id):
                    log(f"    ✅ Successfully queued re-run")
                    success_count += 1
                    time.sleep(1)  # Rate limiting
                else:
                    log(f"    ⚠️  Could not re-run via check-runs API")
            
            if success_count == 0:
                # Fall back to workflow runs API
                log("🔄 Trying workflow runs API instead...")
                failed_workflows = self.get_failed_workflow_runs(pr_number)
                
                if failed_workflows:
                    log(f"Found {len(failed_workflows)} failed workflow runs")
                    for workflow in failed_workflows:
                        workflow_id = workflow.get("id")
                        workflow_name = workflow.get("name")
                        log(f"  Re-running workflow: {workflow_name} (ID: {workflow_id})")
                        
                        if self.rerun_failed_workflow(workflow_id):
                            log(f"    ✅ Successfully queued re-run")
                            time.sleep(1)  # Rate limiting
                else:
                    log("  ⚠️  No workflow runs found to re-run")
            
            log("✅ Re-run requests completed!")
        else:
            log("🔍 DRY RUN - No checks were re-run")
            log("Remove --dry-run flag to actually re-run the checks")


class PRCheckWatcher:
    def __init__(self, rerunner: PRCheckRerunner, pr_number: int,
                 check_interval: int = 30, filter_e2e: bool = True):
        """Initialize the PR check watcher."""
        self.rerunner = rerunner
        self.pr_number = pr_number
        self.check_interval = check_interval
        self.filter_e2e = filter_e2e
        self.retry_count = 0
    
    def wait_for_terminal_state(self) -> bool:
        """Wait for all checks to reach terminal state. Returns True if checks completed."""
        log("⏳ Waiting for all checks to complete...")
        
        while True:
            in_progress = self.rerunner.get_in_progress_checks(self.pr_number)
            
            if not in_progress:
                log("✅ All checks have completed")
                return True
            
            log(f"  {len(in_progress)} checks still in progress... (checking again in {self.check_interval}s)")
            for check in in_progress[:5]:  # Show first 5
                log(f"    ⏳ {check.get('name')}")
            if len(in_progress) > 5:
                log(f"    ... and {len(in_progress) - 5} more")
            
            time.sleep(self.check_interval)
    
    def check_and_retry(self) -> bool:
        """
        Check for failed tests and retry if needed.
        Returns True if all checks passed, False if retries needed or failed.
        """
        # Get failed checks
        if self.filter_e2e:
            failed_checks = self.rerunner.get_e2e_failed_checks(self.pr_number)
            check_type = "e2e/test"
        else:
            failed_checks = self.rerunner.get_failed_checks(self.pr_number)
            check_type = "all"
        
        if not failed_checks:
            log(f"✅ All {check_type} checks passed!")
            return True
        
        log(f"❌ Found {len(failed_checks)} failed {check_type} checks:")
        for check in failed_checks:
            log(f"  ❌ {check.get('name')} - {check.get('conclusion')}")
        
        self.retry_count += 1
        log(f"🔄 Retry attempt {self.retry_count}")
        
        # Trigger re-run
        success_count = 0
        for check in failed_checks:
            check_id = check.get("id")
            check_name = check.get("name")
            log(f"  Re-running: {check_name} (ID: {check_id})")
            
            if self.rerunner.rerun_check(check_id):
                success_count += 1
                time.sleep(1)  # Rate limiting
        
        # If check-runs API didn't work, try workflow runs
        if success_count == 0:
            log("  Trying workflow runs API...")
            failed_workflows = self.rerunner.get_failed_workflow_runs(self.pr_number)
            
            for workflow in failed_workflows:
                workflow_id = workflow.get("id")
                workflow_name = workflow.get("name")
                log(f"  Re-running workflow: {workflow_name} (ID: {workflow_id})")
                
                if self.rerunner.rerun_failed_workflow(workflow_id):
                    success_count += 1
                    time.sleep(1)
        
        if success_count > 0:
            log(f"✅ Triggered re-run for {success_count} check(s)")
        else:
            log("⚠️  Could not trigger re-runs via API")
        
        return False  # Need to keep watching
    
    def run(self) -> int:
        """
        Run the watch loop.
        Returns 0 if all checks passed.
        """
        log(f"👀 Starting check watcher for PR #{self.pr_number}")
        log(f"Check interval: {self.check_interval}s")
        log(f"Filter: {'e2e/test checks only' if self.filter_e2e else 'all checks'}")
        
        # Get initial PR info
        pr_info = self.rerunner.get_pr_info(self.pr_number)
        log(f"PR: {pr_info['title']}")
        log(f"State: {pr_info['state']}")
        log(f"SHA: {pr_info['head']['sha']}")
        
        try:
            while True:
                # Wait for all checks to complete
                self.wait_for_terminal_state()
                
                # Check results and retry if needed
                all_passed = self.check_and_retry()
                
                if all_passed:
                    log("🎉 All checks passed! Exiting.")
                    return 0
                
                # Wait a bit before starting to monitor again
                log(f"⏸️  Waiting {self.check_interval}s before monitoring again...")
                time.sleep(self.check_interval)
        
        except KeyboardInterrupt:
            log("\n⚠️  Interrupted by user. Exiting.")
            return 130


def main():
    parser = argparse.ArgumentParser(
        description="Re-run failed GitHub PR checks with optional continuous monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-time check and retry
  python scripts/rerun_failed_checks.py --pr 347
  
  # Continuous monitoring with auto-retry
  python scripts/rerun_failed_checks.py --pr 347 --watch
  
  # Watch with custom check interval
  python scripts/rerun_failed_checks.py --pr 347 --watch --interval 60
  
  # Dry run to see what would be re-run
  python scripts/rerun_failed_checks.py --pr 347 --dry-run
  
  # Re-run all failed checks (not just e2e)
  python scripts/rerun_failed_checks.py --pr 347 --all-checks
        """
    )
    
    parser.add_argument(
        "--pr",
        type=int,
        required=True,
        help="PR number to check"
    )
    
    parser.add_argument(
        "--token",
        type=str,
        help="GitHub personal access token (or set GITHUB_TOKEN env var)"
    )
    
    parser.add_argument(
        "--repo",
        type=str,
        default="kubefleet-dev/kubefleet",
        help="Repository in format owner/repo (default: kubefleet-dev/kubefleet)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be re-run without actually re-running"
    )
    
    parser.add_argument(
        "--all-checks",
        action="store_true",
        help="Re-run all failed checks, not just e2e/test checks"
    )
    
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously monitor and auto-retry failed checks until all pass"
    )
    
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Check interval in seconds for watch mode (default: 30)"
    )
    
    args = parser.parse_args()
    
    # Check authentication methods in order of priority
    token = args.token or os.getenv("GITHUB_TOKEN")
    use_gh_cli = False
    
    if not token:
        # Try gh CLI as fallback
        if check_gh_auth():
            log("✅ Using authentication from gh CLI")
            use_gh_cli = True
        else:
            log("Error: GitHub authentication is required.")
            log("\nYou can authenticate in one of three ways:")
            log("\n1. Use gh CLI (recommended):")
            log("   gh auth login")
            log("\n2. Set GITHUB_TOKEN environment variable:")
            log("   export GITHUB_TOKEN=ghp_xxx")
            log("\n3. Pass token directly:")
            log("   python scripts/rerun_failed_checks.py --pr 347 --token ghp_xxx")
            log("\nTo create a personal access token:")
            log("1. Go to https://github.com/settings/tokens")
            log("2. Click 'Generate new token (classic)'")
            log("3. Select scopes: 'repo' and 'workflow'")
            sys.exit(1)
    
    try:
        rerunner = PRCheckRerunner(token, args.repo, use_gh_cli=use_gh_cli)
        
        if args.watch:
            # Watch mode - continuous monitoring
            watcher = PRCheckWatcher(
                rerunner,
                args.pr,
                check_interval=args.interval,
                filter_e2e=not args.all_checks
            )
            exit_code = watcher.run()
            sys.exit(exit_code)
        else:
            # One-time mode
            rerunner.process_pr(
                args.pr,
                dry_run=args.dry_run,
                filter_e2e=not args.all_checks
            )
    except requests.exceptions.HTTPError as e:
        log(f"❌ GitHub API Error: {e}")
        if e.response is not None:
            log(f"Response: {e.response.text}")
        sys.exit(1)
    except Exception as e:
        log(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
