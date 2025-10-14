#!/usr/bin/env python3
"""
Canary Scanner - Production-Ready Secret Detection Tool
=======================================================

A powerful, efficient, and user-friendly command-line tool that scans code 
for secrets like API keys, passwords, and tokens.

Features:
- 30+ built-in secret patterns
- Shannon entropy analysis for false positive reduction
- CI/CD integration with proper exit codes
- Docker containerization support
- Rich terminal output with prioritization

Usage:
    python canary.py /path/to/scan
    python canary.py . --output-json
    python canary.py . --ci-mode --fail-on medium

Docker Usage:
    docker run --rm -v "$(pwd):/scan" canary-scanner /scan --ci-mode

Author: Security Engineering Team
Version: 2.0.0
License: MIT
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any

# Third-party imports
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Local imports
from scanner.core import Scanner, Finding
from scanner.patterns import load_patterns

# Configuration constants
PATTERNS_FILE = "patterns.yml"
VERSION = "2.0.0"
DEFAULT_FAIL_ON = "any"

def display_banner():
    """Display the Canary Scanner banner with version information."""
    banner = f"""
[bold cyan]
 ██████╗ █████╗ ███╗   ██╗ █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
██║     ███████║██╔██╗ ██║███████║██████╔╝ ╚████╔╝ 
██║     ██╔══██║██║╚██╗██║██╔══██║██╔══██╗  ╚██╔╝  
╚██████╗██║  ██║██║ ╚████║██║  ██║██║  ██║   ██║   
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
[/bold cyan]
[dim]Scanner v{VERSION} - CI/CD Ready Secret Detection![/dim]
"""
    rprint(banner)

def mask_secret(secret: str, show_chars: int = 4) -> str:
    """
    Mask a secret string for safe display.

    Args:
        secret: The secret string to mask
        show_chars: Number of characters to show at the beginning

    Returns:
        Masked version of the secret (e.g., "AKIA****")
    """
    if len(secret) <= show_chars:
        return "*" * len(secret)
    return secret[:show_chars] + "*" * (len(secret) - show_chars)

def generate_ci_summary(findings: List[Finding]) -> Dict[str, Any]:
    """
    Generate comprehensive CI/CD metadata for automation systems.

    Args:
        findings: List of Finding objects from the scan

    Returns:
        Dictionary containing detailed scan results and metadata
    """
    return {
        "scan_metadata": {
            "scanner_version": VERSION,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "total_findings": len(findings),
            "scan_duration_seconds": 0  # Could be implemented with timing
        },
        "severity_breakdown": {
            "critical": len([f for f in findings if f.confidence == "High"]),
            "medium": len([f for f in findings if f.confidence == "Medium"]), 
            "low": len([f for f in findings if f.confidence == "Low"])
        },
        "metrics": {
            "files_with_secrets": len(set(f.file_path for f in findings)),
            "unique_rule_triggers": len(set(f.rule_id for f in findings)),
            "highest_confidence_level": max([f.confidence for f in findings], default="None")
        },
        "findings": [
            {
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "rule_id": finding.rule_id,
                "description": finding.description,
                "confidence": finding.confidence,
                "secret_preview": mask_secret(finding.matched_string, 6)
            }
            for finding in findings
        ]
    }

def display_results(findings: List[Finding], as_json: bool = False, 
                   verbose: bool = False, ci_mode: bool = False):
    """
    Display scan results with appropriate formatting.

    Args:
        findings: List of detected secrets
        as_json: Output as JSON format
        verbose: Show full secret values (dangerous!)
        ci_mode: CI/CD optimized output with metadata
    """
    console = Console()

    # JSON/CI output mode
    if as_json or ci_mode:
        summary = generate_ci_summary(findings)

        if ci_mode:
            # Add CI-specific decision metadata
            summary["ci_metadata"] = {
                "pipeline_should_fail": len(findings) > 0,
                "blocking_findings": len([f for f in findings if f.confidence in ["High", "Medium"]]),
                "recommended_action": "Block deployment" if findings else "Approve deployment",
                "security_gate_status": "FAIL" if findings else "PASS"
            }

        print(json.dumps(summary, indent=2))
        return

    # Console output mode
    if not findings:
        console.print("\n✅ [bold green]No secrets found! Your code is clean and ready for deployment.[/bold green]\n")
        return

    # Categorize findings by confidence
    high_conf = [f for f in findings if f.confidence == "High"]
    medium_conf = [f for f in findings if f.confidence == "Medium"]
    low_conf = [f for f in findings if f.confidence == "Low"]

    # Display security alert header
    console.print(f"\n🚨 [bold red]SECURITY ALERT: {len(findings)} Potential Secret(s) Detected![/bold red]\n")

    # Show confidence breakdown
    if high_conf:
        console.print(f"[bold red]🔴 CRITICAL: {len(high_conf)} high-confidence secrets found[/bold red]")
    if medium_conf:
        console.print(f"[bold yellow]🟡 MEDIUM: {len(medium_conf)} medium-confidence secrets found[/bold yellow]")
    if low_conf:
        console.print(f"[bold blue]🔵 LOW: {len(low_conf)} low-confidence secrets found[/bold blue]")

    console.print()

    # Create detailed results table
    table = Table(show_header=True, header_style="bold magenta", show_lines=True)
    table.add_column("Priority", style="bold", width=10)
    table.add_column("File", style="cyan", max_width=50)
    table.add_column("Line", style="yellow", width=6)
    table.add_column("Rule ID", style="blue", width=15)
    table.add_column("Description", max_width=35)
    table.add_column("Secret Preview", style="red", max_width=25)

    # Sort by confidence level (Critical first)
    sorted_findings = high_conf + medium_conf + low_conf

    for finding in sorted_findings:
        # Set priority indicator
        priority_map = {
            "High": "🔴 CRITICAL",
            "Medium": "🟡 MEDIUM", 
            "Low": "🔵 LOW"
        }
        priority = priority_map.get(finding.confidence, "❓ UNKNOWN")

        # Mask secrets unless verbose mode (security best practice)
        secret_preview = finding.matched_string if verbose else mask_secret(finding.matched_string, 8)

        # Use relative paths for cleaner display
        try:
            file_display = str(Path(finding.file_path).relative_to(Path.cwd()))
        except ValueError:
            file_display = finding.file_path

        table.add_row(
            priority,
            file_display,
            str(finding.line_number),
            finding.rule_id,
            finding.description,
            secret_preview
        )

    console.print(table)

    # Display remediation guidance
    console.print("\n[bold red]⚠️  IMMEDIATE ACTION REQUIRED:[/bold red]")
    console.print("1. [cyan]🛑 DO NOT MERGE this code until secrets are removed[/cyan]")
    console.print("2. [cyan]🔄 Rotate any exposed credentials immediately[/cyan]")
    console.print("3. [cyan]🗑️  Remove secrets from source code[/cyan]")
    console.print("4. [cyan]🔐 Use environment variables or secure vaults[/cyan]")
    console.print("5. [cyan]📚 Review your organization's secrets management policy[/cyan]")

def validate_environment():
    """
    Validate the runtime environment and dependencies.

    Returns:
        bool: True if environment is valid, False otherwise
    """
    # Check if patterns file exists
    if not os.path.exists(PATTERNS_FILE):
        rprint(f"[bold red]❌ Error: Pattern file '{PATTERNS_FILE}' not found![/bold red]")
        rprint(f"[yellow]📁 Please ensure {PATTERNS_FILE} is in the same directory as canary.py[/yellow]")
        return False

    # Could add more environment checks here (Python version, dependencies, etc.)
    return True

def determine_exit_code(findings: List[Finding], fail_on: str) -> int:
    """
    Determine appropriate exit code based on findings and threshold.

    Args:
        findings: List of detected secrets
        fail_on: Failure threshold ("any", "high", "medium")

    Returns:
        int: Exit code (0=success, 1=security_failure, 2=error)
    """
    if not findings:
        return 0  # Success - no secrets found

    if fail_on == "any":
        return 1  # Fail on any findings
    elif fail_on == "high" and any(f.confidence == "High" for f in findings):
        return 1  # Fail only on high confidence
    elif fail_on == "medium" and any(f.confidence in ["High", "Medium"] for f in findings):
        return 1  # Fail on medium or high confidence

    return 0  # Pass - findings below threshold

def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the command-line argument parser.

    Returns:
        argparse.ArgumentParser: Configured parser
    """
    parser = argparse.ArgumentParser(
        description="Canary Scanner v2.0: Production-Ready Secret Detection",
        epilog="""
Examples:
  %(prog)s .                         # Scan current directory
  %(prog)s /path/to/project          # Scan specific directory  
  %(prog)s file.py --verbose         # Scan single file with details
  %(prog)s . --output-json           # Output results as JSON
  %(prog)s . --ci-mode               # CI/CD optimized output
  %(prog)s . --fail-on high          # Only fail on high-confidence secrets
  docker run -v $(pwd):/scan scanner /scan  # Docker usage
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Positional arguments
    parser.add_argument("path", 
                       help="The file or directory path to scan")

    # Output options
    parser.add_argument("--output-json", action="store_true",
                       help="Output results in JSON format for CI/CD integration")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Show full secret values (⚠️  use with extreme caution)")
    parser.add_argument("--ci-mode", action="store_true",
                       help="CI/CD optimized mode with enhanced metadata")

    # Behavior options
    parser.add_argument("--fail-on", choices=["any", "high", "medium"], 
                       default=DEFAULT_FAIL_ON,
                       help="Set failure threshold (default: %(default)s)")
    parser.add_argument("--patterns-file", default=PATTERNS_FILE,
                       help="Path to patterns file (default: %(default)s)")

    # Information
    parser.add_argument("--version", action="version", 
                       version=f"Canary Scanner {VERSION}")

    return parser

def main():
    """
    Main application entry point with comprehensive error handling.

    Exit Codes:
        0: Success (no secrets found)
        1: Security failure (secrets detected)  
        2: Configuration/runtime error
        130: Interrupted by user (SIGINT)
    """
    # Parse command-line arguments
    parser = create_argument_parser()
    args = parser.parse_args()

    # Show banner unless in quiet modes
    if not (args.output_json or args.ci_mode):
        display_banner()

    # Validate target path exists
    target_path = args.path
    if not os.path.exists(target_path):
        error_msg = f"❌ Error: The path '{target_path}' does not exist."

        if args.output_json or args.ci_mode:
            error_response = {
                "error": "PATH_NOT_FOUND",
                "message": error_msg,
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            }
            print(json.dumps(error_response, indent=2))
        else:
            rprint(f"[bold red]{error_msg}[/bold red]")

        sys.exit(2)

    # Validate environment
    if not validate_environment():
        sys.exit(2)

    # Load secret detection patterns
    try:
        if not (args.output_json or args.ci_mode):
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=Console()
            ) as progress:
                task = progress.add_task("🔍 Loading secret detection patterns...", total=None)
                patterns = load_patterns(args.patterns_file)
        else:
            patterns = load_patterns(args.patterns_file)
    except Exception as e:
        error_msg = f"Failed to load patterns: {e}"

        if args.output_json or args.ci_mode:
            error_response = {
                "error": "PATTERN_LOAD_FAILED",
                "message": error_msg,
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            }
            print(json.dumps(error_response, indent=2))
        else:
            rprint(f"[bold red]❌ {error_msg}[/bold red]")

        sys.exit(2)

    # Validate patterns loaded successfully
    if not patterns:
        warning_msg = "No valid patterns loaded. Scanner may not detect secrets effectively."
        if not (args.output_json or args.ci_mode):
            rprint(f"[bold yellow]⚠️  Warning: {warning_msg}[/bold yellow]")

    # Initialize scanner with loaded patterns
    scanner = Scanner(patterns)
    findings = []

    # Perform the security scan
    try:
        if not (args.output_json or args.ci_mode):
            # Interactive mode with progress indicators
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=Console()
            ) as progress:
                if os.path.isfile(target_path):
                    task = progress.add_task(f"🔍 Scanning file: {os.path.basename(target_path)}...", total=None)
                    findings = list(scanner.scan_file(target_path))
                elif os.path.isdir(target_path):
                    task = progress.add_task(f"🔍 Scanning directory: {target_path}...", total=None)
                    findings = scanner.scan_directory(target_path)
        else:
            # Silent mode for automation
            if os.path.isfile(target_path):
                findings = list(scanner.scan_file(target_path))
            elif os.path.isdir(target_path):
                findings = scanner.scan_directory(target_path)

    except KeyboardInterrupt:
        # Graceful handling of user interruption
        interrupt_msg = "Scan interrupted by user."

        if args.output_json or args.ci_mode:
            error_response = {
                "error": "SCAN_INTERRUPTED",
                "message": interrupt_msg,
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            }
            print(json.dumps(error_response, indent=2))
        else:
            rprint(f"\n[bold yellow]⚠️  {interrupt_msg}[/bold yellow]")

        sys.exit(130)  # Standard SIGINT exit code

    except Exception as e:
        # Handle unexpected scanning errors
        error_msg = f"Scanning failed: {e}"

        if args.output_json or args.ci_mode:
            error_response = {
                "error": "SCAN_FAILED",
                "message": error_msg,
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            }
            print(json.dumps(error_response, indent=2))
        else:
            rprint(f"[bold red]❌ {error_msg}[/bold red]")

        sys.exit(2)

    # Display scan results
    display_results(findings, args.output_json, args.verbose, args.ci_mode)

    # Determine exit code based on findings and threshold
    exit_code = determine_exit_code(findings, args.fail_on)

    # Display final status (unless in quiet modes)
    if not (args.output_json or args.ci_mode):
        if exit_code == 0:
            rprint("\n[bold green]✅ Security scan PASSED - no secrets detected![/bold green]")
            rprint("[bold green]🚀 Ready for deployment.[/bold green]")
        else:
            rprint(f"\n[bold red]❌ Pipeline FAILED: {len(findings)} secret(s) detected![/bold red]")
            rprint("[bold red]🛑 Deployment blocked for security reasons.[/bold red]")

    # Exit with appropriate code for CI/CD systems
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
