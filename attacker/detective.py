"""
detective.py — X-Auth AI  Findings Aggregator & Reporter  v2.0

WHAT CHANGED vs v1:
──────────────────────────────────────────────────────────────────────────────
  1. All dict accesses use .get() with sensible defaults — no KeyError
     even if a module returns a partial result dict.

  2. Handles new result shapes from v2 attacker modules:
       • brute_force results now may include "mode": "playwright" or "http"
       • sqli results now include "injection_point" for JSON-body attacks

  3. New finding type: "SPA Auth Bypass" for Playwright-based brute force wins.

  4. FINDINGS_DIR import has a fallback so the module works stand-alone.

  5. Timestamp uses underscores — no colons (Windows path safety).

  6. _print_final_panel() formats cleanly on narrow terminals.

  7. compile_findings() accepts an optional *meta* dict so main.py can pass
     extra context (target company name, scan mode, etc.) into the report.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table

try:
    from core.config import FINDINGS_DIR
except ImportError:
    FINDINGS_DIR = "lab/results/findings"

console = Console()

_RISK_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim",
}


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def compile_findings(
    sqli_results:  list,
    brute_results: list,
    rate_results:  list,
    target_url:    str,
    meta:          dict | None = None,
) -> dict:
    """
    Aggregates all attack results into a structured findings report.
    Assigns CVSS-aligned severity levels and persists to JSON.

    Args:
        sqli_results:  list of dicts from attacker.sqli_engine.test_sqli()
                       or attacker.juice_shop_adapter.sqli_json()
        brute_results: list of dicts from attacker.brute_force.brute_force()
                       or attacker.juice_shop_adapter.brute_force_json()
                       or attacker.brute_force.brute_force_playwright()
        rate_results:  list of dicts from attacker.rate_limiter_test.test_rate_limiting()
        target_url:    original scan target (for the report header)
        meta:          optional extra context (company name, scan flags, …)

    Returns:
        Full report dict (also written to FINDINGS_DIR/<timestamp>.json)
    """
    os.makedirs(FINDINGS_DIR, exist_ok=True)
    findings: list = []

    # ── SQLi findings ─────────────────────────────────────────────────────────
    for r in (sqli_results or []):
        if not isinstance(r, dict):
            continue
        if r.get("vulnerable"):
            vuln_evidence = [
                x for x in r.get("results", [])
                if isinstance(x, dict) and x.get("vulnerable")
            ]
            injection_point = r.get("injection_point", r.get("target", "unknown"))
            findings.append({
                "type":       "SQL Injection",
                "severity":   "CRITICAL",
                "target":     r.get("target", "unknown"),
                "detail":     (
                    f"{r.get('vuln_count', 0)} payload(s) bypassed authentication"
                    f" via {injection_point}"
                ),
                "cvss_score": 9.8,
                "evidence":   vuln_evidence,
            })

    # ── Brute-force findings ──────────────────────────────────────────────────
    for r in (brute_results or []):
        if not isinstance(r, dict):
            continue
        attempts = r.get("attempts", 0)
        mode     = r.get("mode", "http")   # "http" | "playwright" | "json"

        if r.get("found"):
            creds = r.get("credentials") or {}
            findings.append({
                "type":       "Weak Credentials" if mode != "playwright" else "SPA Auth Bypass",
                "severity":   "CRITICAL",
                "target":     r.get("target", "unknown"),
                "detail":     (
                    f"Login succeeded with "
                    f"{creds.get('username', '?')} / {creds.get('password', '?')} "
                    f"(attempt #{creds.get('attempt', '?')}, mode={mode})"
                ),
                "cvss_score": 9.1,
                "evidence":   [creds],
            })
        else:
            findings.append({
                "type":       "Credential Policy",
                "severity":   "INFO",
                "target":     r.get("target", "unknown"),
                "detail":     f"No weak credentials found after {attempts} attempt(s) (mode={mode})",
                "cvss_score": 0.0,
                "evidence":   [],
            })

    # ── Rate-limiting findings ────────────────────────────────────────────────
    for r in (rate_results or []):
        if not isinstance(r, dict):
            continue
        if r.get("vulnerable"):
            findings.append({
                "type":       "Missing Rate Limiting",
                "severity":   "HIGH",
                "target":     r.get("target", "unknown"),
                "detail":     (
                    f"Accepted {r.get('requests_fired', '?')} requests "
                    f"in {r.get('duration_sec', '?')} s with no blocking "
                    f"({r.get('actual_req_per_sec', 0):.1f} req/s)"
                ),
                "cvss_score": 7.5,
                "evidence":   [{"req_per_sec": r.get("actual_req_per_sec", 0)}],
            })

    # ── Overall risk scoring ──────────────────────────────────────────────────
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count     = sum(1 for f in findings if f["severity"] == "HIGH")
    overall_risk   = (
        "CRITICAL" if critical_count > 0 else
        "HIGH"     if high_count     > 0 else
        "MEDIUM"   if findings             else
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
        "meta":           meta or {},
    }

    # ── Persist ───────────────────────────────────────────────────────────────
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(FINDINGS_DIR, f"findings_{ts}.json")
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    _print_final_panel(report, filename)
    return report


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL DISPLAY
# ─────────────────────────────────────────────────────────────────────────────

def _print_final_panel(report: dict, filename: str):
    risk      = report["overall_risk"]
    color     = _RISK_COLOR.get(risk, "white")
    total     = report["total_findings"]
    critical  = report["critical"]
    high      = report["high"]

    # Findings detail table
    if report["findings"]:
        table = Table(border_style="bright_blue", show_lines=True)
        table.add_column("Severity", style="bold", no_wrap=True)
        table.add_column("Type",     style="cyan")
        table.add_column("Detail",   style="white")

        for f in report["findings"]:
            sev   = f.get("severity", "INFO")
            color_ = _RISK_COLOR.get(sev, "white")
            table.add_row(
                f"[{color_}]{sev}[/{color_}]",
                f.get("type", "—"),
                f.get("detail", "—"),
            )
        console.print(table)

    console.print(Panel(
        f"[{color}]Overall risk  : {risk}[/{color}]\n"
        f"Total findings: {total}  |  "
        f"Critical: {critical}  |  High: {high}\n"
        f"[dim]Saved → {filename}[/dim]",
        title="[bold]X-Auth AI — Scan Complete[/bold]",
        border_style="bright_blue",
    ))