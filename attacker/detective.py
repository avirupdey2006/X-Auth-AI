import json
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.config import FINDINGS_DIR

console = Console()


def compile_findings(
    sqli_results:  list,
    brute_results: list,
    rate_results:  list,
    target_url:    str,
) -> dict:
    """
    Aggregates all attack results into a single structured findings report.
    Assigns severity levels and saves to JSON.
    """
    os.makedirs(FINDINGS_DIR, exist_ok=True)

    findings = []

    # ── SQLi findings ──
    for r in sqli_results:
        if r.get("vulnerable"):
            findings.append({
                "type":        "SQL Injection",
                "severity":    "CRITICAL",
                "target":      r["target"],
                "detail":      f"{r['vuln_count']} payloads bypassed authentication",
                "cvss_score":  9.8,
                "evidence":    [x for x in r["results"] if x.get("vulnerable")],
            })

    # ── Brute force findings ──
    for r in brute_results:
        if r.get("found"):
            creds = r["credentials"]
            findings.append({
                "type":       "Weak Credentials",
                "severity":   "CRITICAL",
                "target":     r["target"],
                "detail":     f"Login succeeded: {creds['username']} / {creds['password']}",
                "cvss_score": 9.1,
                "evidence":   [creds],
            })
        else:
            findings.append({
                "type":       "Credential Policy",
                "severity":   "INFO",
                "target":     r["target"],
                "detail":     f"No weak credentials found in {r['attempts']} attempts",
                "cvss_score": 0,
                "evidence":   [],
            })

    # ── Rate limit findings ──
    for r in rate_results:
        if r.get("vulnerable"):
            findings.append({
                "type":       "Missing Rate Limiting",
                "severity":   "HIGH",
                "target":     r["target"],
                "detail":     f"Accepted {r['requests_fired']} requests in {r['duration_sec']}s with no blocking",
                "cvss_score": 7.5,
                "evidence":   [{"req_per_sec": r["actual_req_per_sec"]}],
            })

    # Risk scoring
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count     = sum(1 for f in findings if f["severity"] == "HIGH")
    overall_risk   = (
        "CRITICAL" if critical_count > 0 else
        "HIGH"     if high_count > 0 else
        "MEDIUM"   if findings else
        "LOW"
    )

    report = {
        "scan_target":    target_url,
        "scan_timestamp": datetime.now().isoformat(),
        "overall_risk":   overall_risk,
        "total_findings": len(findings),
        "critical":       critical_count,
        "high":           high_count,
        "findings":       findings,
    }

    # Save to disk
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(FINDINGS_DIR, f"findings_{ts}.json")
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    _print_final_panel(report, filename)
    return report


def _print_final_panel(report, filename):
    risk_color = {
        "CRITICAL": "bold red",
        "HIGH":     "bold yellow",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }.get(report["overall_risk"], "white")

    console.print(Panel(
        f"[{risk_color}]Overall risk: {report['overall_risk']}[/{risk_color}]\n"
        f"Total findings: {report['total_findings']}  |  "
        f"Critical: {report['critical']}  |  High: {report['high']}\n"
        f"[dim]Saved → {filename}[/dim]",
        title="[bold]X-Auth AI — Phase 2 findings[/bold]",
        border_style="bright_blue",
    ))