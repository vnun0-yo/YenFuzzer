#!/usr/bin/env python3
"""
YenFuzzer — fast directory fuzzer.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import aiohttp
import click
from rich.console import Console
from rich.table import Table
from rich.text import Text


console = Console()


# ─────────────────────────────────────────────────────────────
# Types
# ─────────────────────────────────────────────────────────────


@dataclass(slots=True)
class Response:
    url: str
    status: int
    length: int
    content_type: str
    title: str
    body_hash: str
    location: str | None = None
    error: str | None = None


@dataclass(slots=True)
class Soft404Signature:
    status: int
    length_min: int
    length_max: int
    body_hash: str
    title: str


@dataclass
class Stats:
    total: int = 0
    requests: int = 0
    shown: int = 0
    filtered_soft404: int = 0
    filtered_404: int = 0
    errors: int = 0


# ─────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) YenFuzzer/1.0.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}


def _extract_title(body: bytes, content_type: str) -> str:
    if "html" not in content_type.lower():
        return ""
    head = body[:2048].lower()
    start = head.find(b"<title")
    if start == -1:
        return ""
    start = head.find(b">", start)
    if start == -1:
        return ""
    end = head.find(b"</title", start)
    if end == -1:
        return ""
    return body[start + 1:end].decode("utf-8", errors="ignore").strip()[:150]


def _hash_body(body: bytes) -> str:
    if not body:
        return ""
    return hashlib.md5(body[:4096]).hexdigest()


class HttpClient:
    def __init__(self, *, concurrency: int = 100, timeout: float = 8.0):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=5.0)
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 2,
            limit_per_host=self.concurrency,
            ttl_dns_cache=600,
            ssl=False,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=DEFAULT_HEADERS,
            skip_auto_headers={"Accept-Encoding"},
        )
        return self

    async def __aexit__(self, *exc):
        if self._session:
            await self._session.close()

    async def fetch(self, url: str) -> Response:
        assert self._session
        try:
            async with self._session.get(url, allow_redirects=False) as resp:
                body = await resp.read()
                ct = resp.headers.get("Content-Type", "")
                return Response(
                    url=url,
                    status=resp.status,
                    length=len(body),
                    content_type=ct,
                    title=_extract_title(body, ct),
                    body_hash=_hash_body(body),
                    location=resp.headers.get("Location"),
                )
        except asyncio.TimeoutError:
            return Response(url=url, status=0, length=0, content_type="",
                            title="", body_hash="", error="timeout")
        except Exception as e:
            return Response(url=url, status=0, length=0, content_type="",
                            title="", body_hash="",
                            error=type(e).__name__)


# ─────────────────────────────────────────────────────────────
# Soft-404
# ─────────────────────────────────────────────────────────────


async def build_signature(client: HttpClient, base_url: str) -> Soft404Signature | None:
    base = base_url.rstrip("/")
    urls = [f"{base}/{secrets.token_hex(10)}" for _ in range(2)]
    responses = await asyncio.gather(*(client.fetch(u) for u in urls))

    valid = [r for r in responses if r.error is None]
    if len(valid) < 2:
        return None

    first, second = valid[0], valid[1]

    if first.status != second.status:
        return None
    if first.status == 404:
        return None

    same_body = first.body_hash and first.body_hash == second.body_hash

    length_similar = False
    if first.length > 0:
        diff = abs(first.length - second.length) / max(first.length, 1)
        length_similar = diff < 0.05

    if same_body or length_similar:
        lo = int(min(first.length, second.length) * 0.95)
        hi = int(max(first.length, second.length) * 1.05)
        return Soft404Signature(
            status=first.status,
            length_min=lo,
            length_max=hi,
            body_hash=first.body_hash,
            title=first.title,
        )
    return None


def is_soft404(resp: Response, sig: Soft404Signature | None) -> bool:
    if sig is None or resp.error is not None:
        return False
    if resp.status != sig.status:
        return False
    if resp.body_hash and resp.body_hash == sig.body_hash:
        return True
    if sig.length_min <= resp.length <= sig.length_max:
        if not sig.title or resp.title == sig.title:
            return True
    return False


# ─────────────────────────────────────────────────────────────
# Fuzzer
# ─────────────────────────────────────────────────────────────


ResultCallback = Callable[[str, Response], None]


class Fuzzer:
    def __init__(
        self,
        base_url: str,
        client: HttpClient,
        concurrency: int = 100,
        on_result: ResultCallback | None = None,
    ):
        self.base = base_url.rstrip("/")
        self.client = client
        self.concurrency = concurrency
        self.soft404: Soft404Signature | None = None
        self.stats = Stats()
        self.on_result: ResultCallback = on_result or (lambda p, r: None)

    async def prepare(self):
        self.soft404 = await build_signature(self.client, self.base)

    async def run(self, words: list[str]):
        self.stats.total = len(words)

        queue: asyncio.Queue = asyncio.Queue()
        for w in words:
            queue.put_nowait(w)
        for _ in range(self.concurrency):
            queue.put_nowait(None)

        workers = [
            asyncio.create_task(self._worker(queue))
            for _ in range(self.concurrency)
        ]
        await asyncio.gather(*workers, return_exceptions=True)

    async def _worker(self, queue: asyncio.Queue):
        while True:
            path = await queue.get()
            if path is None:
                return

            url = path if path.startswith(("http://", "https://")) \
                else f"{self.base}/{path.lstrip('/')}"

            try:
                resp = await self.client.fetch(url)
            except Exception:
                self.stats.errors += 1
                continue

            self.stats.requests += 1

            if resp.error:
                self.stats.errors += 1
                continue

            if is_soft404(resp, self.soft404):
                self.stats.filtered_soft404 += 1
                continue

            if resp.status in (403, 404, 410, 0):
                self.stats.filtered_404 += 1
                continue

            self.stats.shown += 1
            try:
                self.on_result(path, resp)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────
# Reporter
# ─────────────────────────────────────────────────────────────


STATUS_STYLE = {
    200: "bold green",
    201: "bold green",
    202: "green",
    204: "green",
    301: "cyan",
    302: "cyan",
    307: "cyan",
    308: "cyan",
    400: "yellow",
    401: "magenta",
    405: "yellow",
    500: "bold red",
    502: "bold red",
    503: "bold red",
}


def emit(path: str, resp: Response):
    style = STATUS_STYLE.get(resp.status, "white")
    line = Text()
    line.append("✅ ", style="bold green")
    line.append(f"[{resp.status}] ", style=style)
    line.append(f"{resp.url:<70} ", style="white")
    line.append(f"({resp.length}b)", style="dim")
    if resp.location:
        line.append(f" → {resp.location[:60]}", style="italic cyan")
    elif resp.title:
        line.append(f"  {resp.title[:50]}", style="italic dim")
    console.print(line, soft_wrap=True)


def summary(stats: Stats):
    table = Table(title="Summary", show_header=False, box=None)
    table.add_row("Total paths", str(stats.total))
    table.add_row("Requests sent", str(stats.requests))
    table.add_row("Found", str(stats.shown))
    table.add_row("Filtered (403/404)", str(stats.filtered_404))
    table.add_row("Filtered (soft-404)", str(stats.filtered_soft404))
    table.add_row("Errors", str(stats.errors))
    console.print()
    console.print(table)


def write_result(f, path: str, resp: Response):
    line = f"✅ [{resp.status}] {resp.url}"
    if resp.length:
        line += f"  ({resp.length}b)"
    if resp.location:
        line += f"  -> {resp.location}"
    f.write(line + "\n")
    f.flush()


# ─────────────────────────────────────────────────────────────
# Wordlist
# ─────────────────────────────────────────────────────────────


def load_wordlist(path: Path, extensions: list[str] | None = None) -> list[str]:
    words = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            words.append(line)

    if not extensions:
        return words

    expanded = []
    for w in words:
        expanded.append(w)
        for ext in extensions:
            expanded.append(f"{w}.{ext}")
    return expanded


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────


@click.command()
@click.version_option("1.0.0")
@click.option("-u", "--url", required=True,
              help="Target URL (e.g., http://target.com:8080)")
@click.option("-w", "--wordlist", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Wordlist file")
@click.option("-x", "--extensions", default=None,
              help="Comma-separated extensions (e.g., php,txt,py)")
@click.option("-o", "--output", default=None,
              type=click.Path(dir_okay=False, path_type=Path),
              help="Save results to file")
def main(url, wordlist, extensions, output):
    """YenFuzzer — fast directory fuzzer."""
    try:
        asyncio.run(_run(url, wordlist, extensions, output))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Fatal error:[/] {e}")
        traceback.print_exc()
        sys.exit(1)


async def _run(url, wordlist, extensions, output):
    console.print(f"[bold cyan]YenFuzzer[/] → {url}")

    # ── Extensions
    ext_list = None
    if extensions:
        ext_list = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
        console.print(f"Extensions: [bold]{', '.join(ext_list)}[/]")

    # ── Wordlist
    words = load_wordlist(wordlist, ext_list)
    if not words:
        console.print("[red]Wordlist is empty[/]")
        return
    console.print(f"Loaded [bold]{len(words)}[/] paths\n")

    # ── Target URL
    # يقبل: http://host:8080 أو host:8080 أو host
    if "://" not in url:
        url = f"http://{url}"

    parsed = urlparse(url)
    if not parsed.hostname:
        console.print("[red]Invalid URL[/]")
        return

    base = url.rstrip("/")

    # ── Output file
    out_file = None
    if output:
        out_file = output.open("w", encoding="utf-8")
        out_file.write(f"# YenFuzzer results for {base}\n\n")

    concurrency = 100

    try:
        async with HttpClient(concurrency=concurrency, timeout=8.0) as client:

            def on_result(path: str, resp: Response):
                emit(path, resp)
                if out_file:
                    write_result(out_file, path, resp)

            fuzzer = Fuzzer(base, client, concurrency=concurrency,
                            on_result=on_result)

            console.print("[dim]Probing soft-404...[/]")
            await fuzzer.prepare()
            if fuzzer.soft404:
                console.print(
                    f"[dim]Soft-404 detected: "
                    f"status={fuzzer.soft404.status}, "
                    f"len≈{fuzzer.soft404.length_min}-{fuzzer.soft404.length_max}[/]\n"
                )
            else:
                console.print("[dim]No soft-404 signature[/]\n")

            console.print("Scanning...\n")
            await fuzzer.run(words)

            summary(fuzzer.stats)
    finally:
        if out_file:
            out_file.close()
            console.print(f"\n[green]Saved to[/] [bold]{output}[/]")


if __name__ == "__main__":
    main()
