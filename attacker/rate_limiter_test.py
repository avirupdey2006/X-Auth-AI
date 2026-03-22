import asyncio
import aiohttp
import time
from rich.console import Console
from rich.table import Table
from core.config import RATE_LIMIT_REQUESTS, RATE_LIMIT_SECONDS, TARGET_TIMEOUT
from bs4 import BeautifulSoup

console = Console()


async def _get_csrf_token(session: aiohttp.ClientSession, url: str) -> dict:
    """Fetch CSRF token and form data"""
    try:
        async with session.get(url, ssl=False) as resp:
            html = await resp.text()
            soup = BeautifulSoup(html, "lxml")
            
            # Find form
            form = soup.find("form")
            if not form:
                return {}
            
            # Extract all input fields
            fields = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    fields[name] = value
            
            # Determine action URL
            action = form.get("action", url)
            if action.startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(url)
                action = f"{parsed.scheme}://{parsed.netloc}{action}"
            elif not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(url, action)
            
            return {"fields": fields, "action": action}
    except Exception:
        return {"fields": {}, "action": url}


async def _fire_request(session: aiohttp.ClientSession, target: dict, idx: int, form_data: dict) -> dict:
    """Fire a single request with proper form data"""
    try:
        # Get fresh CSRF token for each request
        token_data = await _get_csrf_token(session, target["source_page"])
        
        # Prepare data
        data = {
            target["username_field"]: f"xauth_ratelimit_test_{idx}",
            target["password_field"]: "xauth_ratelimit_test",
            **token_data.get("fields", {}),
        }
        
        t_start = time.time()
        async with session.post(
            token_data.get("action", target["action"]),
            data=data,
            timeout=aiohttp.ClientTimeout(total=TARGET_TIMEOUT),
            ssl=False,
            allow_redirects=True
        ) as resp:
            elapsed = time.time() - t_start
            body = await resp.text()
            
            return {
                "index": idx,
                "status_code": resp.status,
                "elapsed": round(elapsed, 3),
                "blocked": resp.status in (429, 403, 503),
                "url": str(resp.url),
                "body_length": len(body),
            }
    except asyncio.TimeoutError:
        return {"index": idx, "status_code": 0, "elapsed": TARGET_TIMEOUT, "blocked": True, "url": target["action"]}
    except Exception as e:
        return {"index": idx, "status_code": 0, "elapsed": 0, "blocked": False, "url": target["action"], "error": str(e)}


async def _run_flood(target: dict, n_requests: int, duration: float) -> list:
    """Run flood with proper rate limiting"""
    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    results = []
    
    async with aiohttp.ClientSession(connector=connector) as session:
        # Calculate delay between requests to achieve target rate
        delay = duration / n_requests if n_requests > 0 else 0.1
        
        for i in range(n_requests):
            # Add small jitter to avoid perfect timing
            await asyncio.sleep(delay + (i % 10) * 0.001)
            
            result = await _fire_request(session, target, i, {})
            results.append(result)
            
            # Don't overwhelm the server
            if i > 0 and i % 20 == 0:
                await asyncio.sleep(0.1)
    
    return results


def test_rate_limiting(target: dict) -> dict:
    """
    Test rate limiting with controlled request pacing.
    """
    n = RATE_LIMIT_REQUESTS
    secs = RATE_LIMIT_SECONDS
    
    console.print(f"\n[bold red]Rate limit test:[/bold red] {target['action']}")
    console.print(f"[dim]Firing {n} requests in {secs}s  ({n/secs:.0f} req/s target)[/dim]\n")
    
    t_start = time.time()
    
    # Run the flood test with proper pacing
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(_run_flood(target, n, secs))
        loop.close()
    except Exception as e:
        console.print(f"[red]Error during rate limit test: {e}[/red]")
        results = []
    
    duration = time.time() - t_start
    
    if not results:
        return {
            "target": target["action"],
            "attack_type": "rate_limit_test",
            "requests_fired": 0,
            "duration_sec": duration,
            "actual_req_per_sec": 0,
            "rate_limiting_active": False,
            "blocked_count": 0,
            "blocking_rate_pct": 0,
            "status_code_breakdown": {},
            "avg_response_ms": 0,
            "vulnerable": True,
        }
    
    blocked_responses = [r for r in results if r.get("blocked")]
    status_codes = {}
    for r in results:
        sc = str(r["status_code"])
        status_codes[sc] = status_codes.get(sc, 0) + 1
    
    rate_limiting_active = len(blocked_responses) > 0
    blocking_rate = len(blocked_responses) / n * 100
    avg_response_time = sum(r["elapsed"] for r in results) / len(results) if results else 0
    
    _print_rate_limit_table(results, status_codes, rate_limiting_active,
                            blocking_rate, duration, n)
    
    return {
        "target": target["action"],
        "attack_type": "rate_limit_test",
        "requests_fired": n,
        "duration_sec": round(duration, 2),
        "actual_req_per_sec": round(n / duration, 1),
        "rate_limiting_active": rate_limiting_active,
        "blocked_count": len(blocked_responses),
        "blocking_rate_pct": round(blocking_rate, 1),
        "status_code_breakdown": status_codes,
        "avg_response_ms": round(avg_response_time * 1000, 1),
        "vulnerable": not rate_limiting_active,
    }


def _print_rate_limit_table(results, status_codes, protected, blocking_rate, duration, n):
    """Print rate limiting results table"""
    verdict = "[bold green]PROTECTED[/bold green]" if protected else "[bold red]VULNERABLE — no rate limiting[/bold red]"
    console.print(f"Verdict: {verdict}")
    console.print(f"Duration: {duration:.2f}s | "
                  f"Actual rate: {n/duration:.1f} req/s | "
                  f"Blocked: {blocking_rate:.1f}%\n")
    
    if results:
        table = Table(title="Status code breakdown", border_style="yellow")
        table.add_column("Status code", style="cyan")
        table.add_column("Count", style="white")
        table.add_column("Meaning", style="dim")
        
        meanings = {
            "200": "Request succeeded — no blocking",
            "302": "Redirect — login processed",
            "429": "Too Many Requests — rate limited",
            "403": "Forbidden — IP/account blocked",
            "503": "Service unavailable — server overwhelmed",
            "0": "Connection error / timeout",
        }
        for code, count in sorted(status_codes.items()):
            table.add_row(code, str(count), meanings.get(code, "—"))
        
        console.print(table)