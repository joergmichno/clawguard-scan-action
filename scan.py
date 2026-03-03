#!/usr/bin/env python3
"""
ClawGuard Shield — GitHub Action Scanner

Scans repository files for prompt injection vulnerabilities using the
ClawGuard Shield API. Designed to run as a GitHub Action.

Exit codes:
    0 — All clean, or findings below threshold
    1 — Findings at or above the fail-on severity
    2 — Configuration or API error
"""

import glob
import json
import os
import sys
import time

import requests

# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------

API_KEY = os.environ.get("CLAWGUARD_API_KEY", "")
API_URL = os.environ.get("CLAWGUARD_API_URL", "https://prompttools.co/api/v1").rstrip("/")
PATHS = os.environ.get("CLAWGUARD_PATHS", "**/*.py\n**/*.js\n**/*.ts").strip()
FAIL_ON = os.environ.get("CLAWGUARD_FAIL_ON", "HIGH").upper()
SCAN_MODE = os.environ.get("CLAWGUARD_SCAN_MODE", "prompts")
MAX_FILE_SIZE = int(os.environ.get("CLAWGUARD_MAX_FILE_SIZE", "50000"))
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")
GITHUB_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY", "")

SEVERITY_ORDER = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Heuristic patterns that indicate a file might contain prompts
PROMPT_INDICATORS = [
    "system_prompt", "system_message", "system prompt",
    "user_prompt", "user_message",
    "prompt_template", "prompt =",
    "PROMPT", "instruction",
    "You are a", "You are an",
    "As an AI", "As a helpful",
    '"role"', "'role'", "role: system", "role: user", "role: assistant",
    "<<SYS>>", "[INST]",
    "Human:", "Assistant:",
]


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def log(msg: str, level: str = "info"):
    """Print GitHub Actions-compatible log messages."""
    if level == "error":
        print(f"::error::{msg}")
    elif level == "warning":
        print(f"::warning::{msg}")
    elif level == "debug":
        print(f"::debug::{msg}")
    else:
        print(msg)


def set_output(name: str, value: str):
    """Set a GitHub Actions output variable."""
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{name}={value}\n")


def write_summary(markdown: str):
    """Write to the GitHub Actions step summary."""
    if GITHUB_STEP_SUMMARY:
        with open(GITHUB_STEP_SUMMARY, "a") as f:
            f.write(markdown + "\n")


def severity_at_or_above(severity: str, threshold: str) -> bool:
    """Check if severity meets or exceeds the threshold."""
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


def looks_like_prompt(content: str) -> bool:
    """Heuristic check if file content likely contains prompts."""
    content_lower = content.lower()
    return any(indicator.lower() in content_lower for indicator in PROMPT_INDICATORS)


def collect_files() -> list[str]:
    """Collect files matching the configured glob patterns."""
    patterns = [p.strip() for p in PATHS.split("\n") if p.strip()]
    files = set()
    for pattern in patterns:
        matched = glob.glob(pattern, recursive=True)
        files.update(matched)
    return sorted(files)


def scan_text(text: str, source: str = "github-action") -> dict | None:
    """Send text to the Shield API for scanning."""
    try:
        resp = requests.post(
            f"{API_URL}/scan",
            headers={
                "X-API-Key": API_KEY,
                "Content-Type": "application/json",
                "User-Agent": "clawguard-scan-action/1.0",
            },
            json={"text": text, "source": source},
            timeout=15,
        )
        if resp.status_code == 429:
            log("Rate limit reached. Waiting 2 seconds...", "warning")
            time.sleep(2)
            return scan_text(text, source)  # retry once
        if resp.status_code != 200:
            log(f"API returned {resp.status_code}: {resp.text}", "warning")
            return None
        return resp.json()
    except requests.RequestException as e:
        log(f"API request failed: {e}", "error")
        return None


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main():
    # Validate config
    if not API_KEY:
        log("CLAWGUARD_API_KEY is not set. Get a free key at https://prompttools.co/shield", "error")
        sys.exit(2)

    if not API_KEY.startswith("cgs_"):
        log("Invalid API key format. Keys start with 'cgs_'.", "error")
        sys.exit(2)

    if FAIL_ON not in SEVERITY_ORDER and FAIL_ON != "NONE":
        log(f"Invalid fail-on severity: {FAIL_ON}. Use CRITICAL, HIGH, MEDIUM, LOW, or NONE.", "error")
        sys.exit(2)

    # Health check
    log("Checking ClawGuard Shield API health...")
    try:
        health = requests.get(f"{API_URL}/health", timeout=10)
        if health.status_code != 200:
            log(f"API health check failed (HTTP {health.status_code})", "error")
            sys.exit(2)
        health_data = health.json()
        log(f"API healthy — {health_data.get('patterns_count', '?')} patterns loaded")
    except requests.RequestException as e:
        log(f"Cannot reach API at {API_URL}: {e}", "error")
        sys.exit(2)

    # Collect files
    files = collect_files()
    if not files:
        log("No files matched the configured patterns.", "warning")
        set_output("total-files", "0")
        set_output("total-findings", "0")
        set_output("max-severity", "CLEAN")
        sys.exit(0)

    log(f"Found {len(files)} files matching patterns")

    # Scan
    results = []
    scanned = 0
    skipped_size = 0
    skipped_mode = 0
    total_findings = 0
    max_severity = "CLEAN"

    for filepath in files:
        # Skip binary/large files
        try:
            size = os.path.getsize(filepath)
            if size > MAX_FILE_SIZE:
                skipped_size += 1
                log(f"  SKIP (too large: {size}B) {filepath}", "debug")
                continue
            if size == 0:
                continue

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError) as e:
            log(f"  SKIP (read error) {filepath}: {e}", "debug")
            continue

        # In prompt mode, skip files that don't look like they contain prompts
        if SCAN_MODE == "prompts" and not looks_like_prompt(content):
            skipped_mode += 1
            continue

        # Scan the file
        result = scan_text(content, source=f"github-action:{filepath}")
        if result is None:
            continue

        scanned += 1
        findings_count = result.get("findings_count", 0)
        severity = result.get("severity", "CLEAN")

        if findings_count > 0:
            total_findings += findings_count
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
                max_severity = severity

            # Annotate findings
            for finding in result.get("findings", []):
                f_severity = finding.get("severity", "UNKNOWN")
                f_pattern = finding.get("pattern_name", "unknown")
                f_line = finding.get("line_number", 0)
                f_desc = finding.get("description", "")

                level = "error" if severity_at_or_above(f_severity, "HIGH") else "warning"
                log(f"::{level} file={filepath},line={f_line}::[{f_severity}] {f_pattern}: {f_desc}")

            results.append({
                "file": filepath,
                "severity": severity,
                "risk_score": result.get("risk_score", 0),
                "findings": result.get("findings", []),
            })
        else:
            log(f"  CLEAN {filepath}")

    # Summary
    log("")
    log("=" * 60)
    log("ClawGuard Shield Scan Results")
    log("=" * 60)
    log(f"Files scanned:    {scanned}")
    log(f"Files skipped:    {skipped_size} (too large) + {skipped_mode} (no prompts)")
    log(f"Total findings:   {total_findings}")
    log(f"Max severity:     {max_severity}")
    log(f"Fail threshold:   {FAIL_ON}")
    log("=" * 60)

    if results:
        log("")
        log("Files with findings:")
        for r in sorted(results, key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True):
            log(f"  [{r['severity']}] {r['file']} (risk: {r['risk_score']}/10, {len(r['findings'])} findings)")

    # Write JSON report
    report_path = "clawguard-report.json"
    report = {
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_url": API_URL,
        "files_scanned": scanned,
        "total_findings": total_findings,
        "max_severity": max_severity,
        "fail_threshold": FAIL_ON,
        "results": results,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    log(f"\nFull report: {report_path}")

    # Set outputs
    set_output("total-files", str(scanned))
    set_output("total-findings", str(total_findings))
    set_output("max-severity", max_severity)
    set_output("report", report_path)

    # Write step summary
    summary_lines = [
        "## ClawGuard Shield Scan Results\n",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Files scanned | {scanned} |",
        f"| Total findings | {total_findings} |",
        f"| Max severity | {max_severity} |",
        f"| Fail threshold | {FAIL_ON} |",
        "",
    ]

    if results:
        summary_lines.append("### Findings\n")
        summary_lines.append("| File | Severity | Risk | Findings |")
        summary_lines.append("|------|----------|------|----------|")
        for r in sorted(results, key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True):
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(r["severity"], "⚪")
            summary_lines.append(
                f"| `{r['file']}` | {emoji} {r['severity']} | {r['risk_score']}/10 | {len(r['findings'])} |"
            )
        summary_lines.append("")

    if total_findings == 0:
        summary_lines.append("✅ **No security findings detected.**\n")
    elif FAIL_ON != "NONE" and severity_at_or_above(max_severity, FAIL_ON):
        summary_lines.append(f"❌ **Scan failed:** Found {max_severity} severity (threshold: {FAIL_ON})\n")
    else:
        summary_lines.append(f"⚠️ **{total_findings} findings found** but below fail threshold ({FAIL_ON})\n")

    summary_lines.append(
        "*Scanned by [ClawGuard Shield](https://prompttools.co/shield) "
        "— AI Agent Security Scanning API*"
    )
    write_summary("\n".join(summary_lines))

    # Exit code
    if FAIL_ON == "NONE":
        sys.exit(0)

    if severity_at_or_above(max_severity, FAIL_ON):
        log(f"\nFAILED: Found {max_severity} severity findings (threshold: {FAIL_ON})", "error")
        sys.exit(1)

    log(f"\nPASSED: No findings at or above {FAIL_ON} severity")
    sys.exit(0)


if __name__ == "__main__":
    main()
