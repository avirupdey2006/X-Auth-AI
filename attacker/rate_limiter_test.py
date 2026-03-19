import asyncio
import aiohttp
import time
from rich.console import Console
from rich.table import Table
from core.config import RATE_LIMIT_REQUESTS, RATE_LIMIT_SECONDS, TARGET_TIMEOUT

console = Console()


async def _fire_request(session: aiohttp.ClientSession, url: str,
                         data: dict, idx: int) -> dict:
    try:
        t = time.time()
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=TARGET_TIMEOUT),
                                ssl=False, allow_redirects=True) as resp:
            elapsed = time.time() - t
            body    = await resp.text()
            return {
                "index":       idx,
                "status_code": resp.status,
                "elapsed":     round(elapsed, 3),
                "blocked":     resp.status in (429, 403, 503),
                "url":         str(resp.url),
            }
    except asyncio.TimeoutError:
        return {"index": idx, "status_code": 0, "elapsed": TARGET_TIMEOUT,
                "blocked": True, "url": url}
    except Exception as e:
        return {"index": idx, "status_code": 0, "elapsed": 0,
                "blocked": False, "url": url, "error": str(e)}


async def _run_flood(target: dict, n_requests: int) -> list:
    dummy_data = {
        target["username_field"]: "xauth_ratelimit_test",
        target["password_field"]: "xauth_ratelimit_test",
        **target.get("extra_fields", {}),
    }
    connector = aiohttp.TCPConnector(limit=n_requests, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _fire_request(session, target["action"], dummy_data, i)
            for i in range(n_requests)
        ]
        return await asyncio.gather(*tasks)


def test_rate_limiting(target: dict) -> dict:
    """
    Fires RATE_LIMIT_REQUESTS requests in RATE_LIMIT_SECONDS seconds.
    Detects if rate limiting is active (429/403/503 responses).
    """
    n    = RATE_LIMIT_REQUESTS
    secs = RATE_LIMIT_SECONDS

    console.print(f"\n[bold red]Rate limit test:[/bold red] {target['action']}")
    console.print(f"[dim]Firing {n} requests in {secs}s  ({n/secs:.0f} req/s)[/dim]\n")

    t_start  = time.time()
    results  = asyncio.run(_run_flood(target, n))
    duration = time.time() - t_start

    blocked_responses   = [r for r in results if r.get("blocked")]
    status_codes        = {}
    for r in results:
        sc = str(r["status_code"])
        status_codes[sc] = status_codes.get(sc, 0) + 1

    rate_limiting_active = len(blocked_responses) > 0
    blocking_rate        = len(blocked_responses) / n * 100
    avg_response_time    = sum(r["elapsed"] for r in results) / len(results)

    _print_rate_limit_table(results, status_codes, rate_limiting_active,
                            blocking_rate, duration, n)

    return {
        "target":                target["action"],
        "attack_type":           "rate_limit_test",
        "requests_fired":        n,
        "duration_sec":          round(duration, 2),
        "actual_req_per_sec":    round(n / duration, 1),
        "rate_limiting_active":  rate_limiting_active,
        "blocked_count":         len(blocked_responses),
        "blocking_rate_pct":     round(blocking_rate, 1),
        "status_code_breakdown": status_codes,
        "avg_response_ms":       round(avg_response_time * 1000, 1),
        "vulnerable":            not rate_limiting_active,
    }


def _print_rate_limit_table(results, status_codes, protected,
                             blocking_rate, duration, n):
    verdict = "[bold green]PROTECTED[/bold green]" if protected else "[bold red]VULNERABLE — no rate limiting[/bold red]"
    console.print(f"Verdict: {verdict}")
    console.print(f"Duration: {duration:.2f}s | "
                  f"Actual rate: {n/duration:.1f} req/s | "
                  f"Blocked: {blocking_rate:.1f}%\n")

    table = Table(title="Status code breakdown", border_style="yellow")
    table.add_column("Status code", style="cyan")
    table.add_column("Count",       style="white")
    table.add_column("Meaning",     style="dim")

    meanings = {
        "200": "Request succeeded — no blocking",
        "302": "Redirect — login processed",
        "429": "Too Many Requests — rate limited",
        "403": "Forbidden — IP/account blocked",
        "503": "Service unavailable — server overwhelmed",
        "0":   "Connection error / timeout",
    }
    for code, count in sorted(status_codes.items()):
        table.add_row(code, str(count), meanings.get(code, "—"))

    console.print(table)