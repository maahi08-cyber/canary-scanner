#!/usr/bin/env python3
"""
Canary Scanner - Enhanced with Dashboard Integration (Phase 3)
=============================================================

Production-ready secret detection tool with comprehensive CI/CD integration
and real-time dashboard reporting capabilities.

NEW Phase 3 Features:
- Dashboard API integration for centralized findings management
- Enhanced JSON output with metadata for web dashboard
- Automatic finding submission to dashboard server
- Repository-aware scanning with commit context
- Improved error handling and logging for CI/CD environments

Version: 3.0.0 (Phase 3: Dashboard Integration)
Author: Security Engineering Team
License: MIT
"""

import argparse
import json
import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

# Import scanner components
from scanner import Scanner, Finding, load_patterns

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Rich console
console = Console()

# Version information
__version__ = "3.0.0"
__phase__ = "Dashboard Integration"

class CanaryScanner:
    """
    Enhanced Canary Scanner with dashboard integration capabilities.

    Features:
    - Multi-output support (console, JSON, dashboard)
    - CI/CD optimized execution modes
    - Real-time dashboard reporting
    - Repository context awareness
    - Advanced error handling and recovery
    """

    def __init__(self, patterns_file: str = "patterns.yml"):
        """Initialize the scanner with enhanced capabilities."""
        self.patterns_file = patterns_file
        self.scanner = None
        self.patterns = []
        self.scan_start_time = None
        self.scan_metadata = {}

        # Dashboard integration settings
        self.dashboard_url = None
        self.repository_name = None
        self.commit_hash = None
        self.branch = None

        self._initialize_scanner()

    def _initialize_scanner(self):
        """Initialize the scanner engine with patterns."""
        try:
            self.patterns = load_patterns(self.patterns_file)
            self.scanner = Scanner(self.patterns)
            logger.info(f"✅ Initialized scanner with {len(self.patterns)} patterns")
        except Exception as e:
            logger.error(f"❌ Failed to initialize scanner: {e}")
            raise

    def configure_dashboard_integration(self, dashboard_url: str, repository: str, 
                                      commit: str = None, branch: str = None):
        """Configure dashboard integration settings."""
        self.dashboard_url = dashboard_url
        self.repository_name = repository
        self.commit_hash = commit or os.getenv('GITHUB_SHA', 'unknown')
        self.branch = branch or os.getenv('GITHUB_REF_NAME', 'unknown')

        logger.info(f"🔗 Dashboard integration configured: {dashboard_url}")
        logger.info(f"📁 Repository: {repository} ({branch})")

    def scan_target(self, target_path: str, **options) -> Dict[str, Any]:
        """
        Scan a target path and return comprehensive results.

        Args:
            target_path: Path to scan (file or directory)
            **options: Additional scanning options

        Returns:
            dict: Comprehensive scan results with metadata
        """
        self.scan_start_time = datetime.utcnow()

        try:
            # Determine scan type
            if os.path.isfile(target_path):
                findings = list(self.scanner.scan_file(target_path))
                scan_type = "file"
            elif os.path.isdir(target_path):
                findings = self.scanner.scan_directory(target_path)
                scan_type = "directory"
            else:
                raise FileNotFoundError(f"Target path does not exist: {target_path}")

            # Calculate scan duration
            scan_end_time = datetime.utcnow()
            scan_duration = (scan_end_time - self.scan_start_time).total_seconds()

            # Generate comprehensive results
            results = self._generate_scan_results(
                findings=findings,
                target_path=target_path,
                scan_type=scan_type,
                scan_duration=scan_duration,
                **options
            )

            logger.info(f"✅ Scan completed: {len(findings)} findings in {scan_duration:.2f}s")
            return results

        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            raise

    def _generate_scan_results(self, findings: List[Finding], target_path: str, 
                             scan_type: str, scan_duration: float, **options) -> Dict[str, Any]:
        """Generate comprehensive scan results with metadata."""

        # Categorize findings by confidence
        findings_by_confidence = {"High": [], "Medium": [], "Low": []}
        for finding in findings:
            findings_by_confidence[finding.confidence].append(finding)

        # Calculate statistics
        stats = self.scanner.get_scan_statistics()

        # Prepare findings data
        findings_data = []
        for finding in findings:
            finding_data = {
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "rule_id": finding.rule_id,
                "description": finding.description,
                "confidence": finding.confidence,
                "secret_preview": self._mask_secret(finding.matched_string, options.get('verbose', False))
            }
            findings_data.append(finding_data)

        # Generate comprehensive results
        results = {
            "scan_metadata": {
                "scanner_version": __version__,
                "scan_timestamp": self.scan_start_time.isoformat() + "Z",
                "target_path": str(target_path),
                "scan_type": scan_type,
                "scan_duration_seconds": scan_duration,
                "total_findings": len(findings),
                "patterns_loaded": len(self.patterns)
            },
            "repository_context": {
                "repository_name": self.repository_name,
                "commit_hash": self.commit_hash,
                "branch": self.branch
            } if self.repository_name else None,
            "severity_breakdown": {
                "critical": len(findings_by_confidence["High"]),
                "medium": len(findings_by_confidence["Medium"]),
                "low": len(findings_by_confidence["Low"])
            },
            "scanner_statistics": stats,
            "findings": findings_data,
            "ci_metadata": {
                "pipeline_should_fail": len(findings) > 0,
                "recommended_action": "Block deployment" if findings_by_confidence["High"] else "Review findings",
                "exit_code": self._calculate_exit_code(findings, options.get('fail_on', 'any'))
            }
        }

        return results

    def _mask_secret(self, secret: str, verbose: bool = False) -> str:
        """Mask secret for safe display."""
        if verbose:
            return secret

        if len(secret) <= 8:
            return "*" * len(secret)

        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _calculate_exit_code(self, findings: List[Finding], fail_on: str) -> int:
        """Calculate appropriate exit code based on findings and threshold."""
        if not findings:
            return 0  # Success - no secrets found

        if fail_on == "any":
            return 1  # Fail on any finding
        elif fail_on == "high":
            return 1 if any(f.confidence == "High" for f in findings) else 0
        elif fail_on == "medium":
            high_or_medium = any(f.confidence in ["High", "Medium"] for f in findings)
            return 1 if high_or_medium else 0

        return 1  # Default: fail on findings

    async def send_to_dashboard(self, results: Dict[str, Any]) -> bool:
        """Send scan results to dashboard server."""
        if not self.dashboard_url:
            logger.debug("No dashboard URL configured, skipping dashboard submission")
            return True

        try:
            # Prepare payload for dashboard API
            payload = {
                "repository_name": self.repository_name,
                "commit_hash": self.commit_hash,
                "branch": self.branch,
                "scan_metadata": results["scan_metadata"],
                "findings": results["findings"]
            }

            # Send to dashboard API
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.dashboard_url}/api/v1/scan",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    dashboard_response = response.json()
                    logger.info(f"✅ Successfully sent results to dashboard")
                    logger.info(f"🔗 View results: {dashboard_response.get('results_url')}")

                    # Add dashboard info to results
                    results["dashboard_info"] = {
                        "submitted": True,
                        "scan_id": dashboard_response.get("scan_id"),
                        "results_url": dashboard_response.get("results_url")
                    }

                    return True
                else:
                    logger.error(f"❌ Dashboard submission failed: {response.status_code}")
                    logger.error(f"Response: {response.text}")
                    return False

        except Exception as e:
            logger.error(f"❌ Error sending to dashboard: {e}")
            return False

    def display_console_results(self, results: Dict[str, Any], ci_mode: bool = False):
        """Display results in the console with rich formatting."""
        findings = results["findings"]
        scan_metadata = results["scan_metadata"]
        severity_breakdown = results["severity_breakdown"]

        if ci_mode:
            # CI-optimized output
            self._display_ci_results(results)
        else:
            # Rich interactive output
            self._display_rich_results(results)

    def _display_ci_results(self, results: Dict[str, Any]):
        """Display results optimized for CI/CD environments."""
        findings = results["findings"]
        severity_breakdown = results["severity_breakdown"]

        if not findings:
            console.print("✅ [green]SECURITY SCAN PASSED[/green]")
            console.print("🎉 No secrets detected. Code is secure and ready for deployment.")
            return

        console.print(f"🚨 [red]SECURITY SCAN FAILED[/red]")
        console.print(f"Found {len(findings)} potential secret(s):")
        console.print(f"  🔴 Critical: {severity_breakdown['critical']}")
        console.print(f"  🟡 Medium: {severity_breakdown['medium']}")
        console.print(f"  🔵 Low: {severity_breakdown['low']}")
        console.print()

        # Display findings in compact format
        for i, finding in enumerate(findings, 1):
            priority = "🔴 CRITICAL" if finding["confidence"] == "High" else "🟡 MEDIUM" if finding["confidence"] == "Medium" else "🔵 LOW"
            console.print(f"{i}. {priority} - {finding['file_path']}:{finding['line_number']}")
            console.print(f"   Rule: {finding['rule_id']} - {finding['description']}")
            console.print(f"   Secret: {finding['secret_preview']}")
            console.print()

        console.print("⚠️  [yellow]IMMEDIATE ACTION REQUIRED:[/yellow]")
        console.print("1. 🛑 DO NOT MERGE this code until secrets are removed")
        console.print("2. 🔄 Rotate any exposed credentials immediately")
        console.print("3. 🗑️ Remove secrets from source code")
        console.print("4. 🔐 Use environment variables or secure vaults")

    def _display_rich_results(self, results: Dict[str, Any]):
        """Display results with rich formatting for interactive use."""
        findings = results["findings"]
        scan_metadata = results["scan_metadata"]
        severity_breakdown = results["severity_breakdown"]

        # Header
        if findings:
            title = f"🚨 SECURITY ALERT: {len(findings)} Potential Secret(s) Detected!"
            header_style = "red"
        else:
            title = "✅ Security Scan Complete: No Secrets Detected!"
            header_style = "green"

        console.print(Panel(title, style=header_style))

        if not findings:
            console.print("🎉 [green]Congratulations! Your code is clean and secure.[/green]")
            console.print("🚀 [green]Safe to deploy and merge.[/green]")
            return

        # Severity summary
        summary_text = Text()
        if severity_breakdown["critical"] > 0:
            summary_text.append(f"🔴 CRITICAL: {severity_breakdown['critical']} high-confidence secrets found\n", style="red bold")
        if severity_breakdown["medium"] > 0:
            summary_text.append(f"🟡 MEDIUM: {severity_breakdown['medium']} medium-confidence secrets found\n", style="yellow bold")
        if severity_breakdown["low"] > 0:
            summary_text.append(f"🔵 LOW: {severity_breakdown['low']} low-confidence secrets found\n", style="blue bold")

        console.print(summary_text)

        # Findings table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Priority", style="bold", width=12)
        table.add_column("File", style="cyan", width=25)
        table.add_column("Line", justify="center", width=6)
        table.add_column("Rule ID", style="yellow", width=15)
        table.add_column("Description", width=30)
        table.add_column("Secret Preview", style="red", width=25)

        for finding in findings:
            # Style based on confidence
            if finding["confidence"] == "High":
                priority = "[red]🔴 CRITICAL[/red]"
            elif finding["confidence"] == "Medium":
                priority = "[yellow]🟡 MEDIUM[/yellow]"
            else:
                priority = "[blue]🔵 LOW[/blue]"

            # Truncate long paths
            file_path = finding["file_path"]
            if len(file_path) > 23:
                file_path = f"...{file_path[-20:]}"

            # Truncate long descriptions
            description = finding["description"]
            if len(description) > 28:
                description = f"{description[:25]}..."

            table.add_row(
                priority,
                file_path,
                str(finding["line_number"]),
                finding["rule_id"],
                description,
                finding["secret_preview"]
            )

        console.print(table)

        # Action items
        console.print()
        action_panel = Panel(
            """⚠️  IMMEDIATE ACTION REQUIRED:
1. 🛑 DO NOT MERGE this code until secrets are removed
2. 🔄 Rotate any exposed credentials immediately
3. 🗑️ Remove secrets from source code
4. 🔐 Use environment variables or secure vaults
5. 📚 Review your organization's secrets management policy""",
            title="Security Response",
            style="yellow"
        )
        console.print(action_panel)

        # Dashboard link if available
        dashboard_info = results.get("dashboard_info")
        if dashboard_info and dashboard_info.get("results_url"):
            console.print(f"\n🔗 [blue]View detailed results: {dashboard_info['results_url']}[/blue]")

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser with enhanced options."""
    parser = argparse.ArgumentParser(
        description="Canary Scanner - Advanced secret detection with dashboard integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s .                                    # Scan current directory
  %(prog)s /path/to/project --ci-mode           # CI/CD optimized mode
  %(prog)s . --output-json --fail-on medium    # JSON output, fail on medium+
  %(prog)s . --report-url https://dashboard.example.com --repository org/repo
        """
    )

    # Required arguments
    parser.add_argument(
        "path",
        help="The file or directory path to scan"
    )

    # Output options
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Output results in JSON format for CI/CD integration"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full secret values (⚠️ use with extreme caution)"
    )

    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="CI/CD optimized mode with enhanced metadata and compact output"
    )

    # Failure thresholds
    parser.add_argument(
        "--fail-on",
        choices=["any", "high", "medium"],
        default="any",
        help="Set failure threshold (default: any)"
    )

    # Configuration options
    parser.add_argument(
        "--patterns-file",
        default="patterns.yml",
        help="Path to patterns file (default: patterns.yml)"
    )

    # Dashboard integration (Phase 3)
    parser.add_argument(
        "--report-url",
        help="Dashboard API URL for centralized reporting"
    )

    parser.add_argument(
        "--repository",
        help="Repository name (org/repo format) for dashboard integration"
    )

    parser.add_argument(
        "--commit",
        help="Commit hash (defaults to GITHUB_SHA environment variable)"
    )

    parser.add_argument(
        "--branch", 
        help="Branch name (defaults to GITHUB_REF_NAME environment variable)"
    )

    # Version information
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__} ({__phase__})"
    )

    return parser

async def main() -> int:
    """
    Main entry point with enhanced error handling and dashboard integration.

    Returns:
        int: Exit code (0=success, 1=secrets found, 2=error, 130=interrupted)
    """
    parser = create_argument_parser()
    args = parser.parse_args()

    try:
        # Validate target path
        if not os.path.exists(args.path):
            console.print(f"❌ [red]Error: Path does not exist: {args.path}[/red]", file=sys.stderr)
            return 2

        # Initialize scanner
        scanner = CanaryScanner(args.patterns_file)

        # Configure dashboard integration if provided
        if args.report_url:
            if not args.repository:
                console.print("❌ [red]Error: --repository is required when using --report-url[/red]", file=sys.stderr)
                return 2

            scanner.configure_dashboard_integration(
                dashboard_url=args.report_url,
                repository=args.repository,
                commit=args.commit,
                branch=args.branch
            )

        # Perform scan
        if not args.output_json and not args.ci_mode:
            console.print(f"🔍 [blue]Scanning {args.path}...[/blue]")

        results = scanner.scan_target(
            args.path,
            verbose=args.verbose,
            fail_on=args.fail_on,
            ci_mode=args.ci_mode
        )

        # Send to dashboard if configured
        dashboard_success = True
        if args.report_url:
            dashboard_success = await scanner.send_to_dashboard(results)

        # Output results
        if args.output_json:
            print(json.dumps(results, indent=2))
        else:
            scanner.display_console_results(results, ci_mode=args.ci_mode)

        # Determine exit code
        exit_code = results["ci_metadata"]["exit_code"]

        # Warn if dashboard submission failed (but don't fail the scan)
        if args.report_url and not dashboard_success:
            console.print("⚠️  [yellow]Warning: Failed to submit results to dashboard[/yellow]", file=sys.stderr)

        return exit_code

    except KeyboardInterrupt:
        console.print("\n🛑 [yellow]Scan interrupted by user[/yellow]", file=sys.stderr)
        return 130

    except FileNotFoundError as e:
        console.print(f"❌ [red]Error: {e}[/red]", file=sys.stderr)
        return 2

    except Exception as e:
        logger.exception("Unexpected error during scan")
        console.print(f"❌ [red]Unexpected error: {e}[/red]", file=sys.stderr)
        return 2

if __name__ == "__main__":
    import asyncio
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        sys.exit(130)
