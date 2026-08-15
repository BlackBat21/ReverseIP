#!/usr/bin/env python3
"""
RECON </Lanz_VibeCoder> - Reverse IP Lookup service.

A lightweight, single-process FastAPI application that performs reverse IP
lookups (PTR records + optional shared-hosting API fallback) across a CIDR
range, a single IP, or a domain. Scans run asynchronously in the background;
results are written as flat, deduplicated hostname lists under RESULTS_DIR.

Designed for a 1 GB / low-memory Ubuntu VPS:
  * no Redis / Celery / database - asyncio + in-memory job table + flat files
  * bounded concurrency via a fixed worker pool (memory stays flat regardless
    of range size)
  * single uvicorn worker

Every data/action API endpoint is protected with HTTP Basic Auth.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.resolver
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, field_validator

try:
    import httpx  # optional: only needed for the external API fallback
except ImportError:
    httpx = None

try:
    # Used to parse the DER certificate we grab from a target IP. Without CA
    # validation stdlib ssl.getpeercert() returns {}, so we need a real parser.
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None
    NameOID = None

# --------------------------------------------------------------------------- #
# Configuration - everything comes from environment variables so no secret
# is ever hard-coded into the source.
# --------------------------------------------------------------------------- #
def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
RESULTS_DIR = Path(_env("RECON_RESULTS_DIR", "/var/www/recon/results")).resolve()

AUTH_USER = _env("RECON_USER", "admin")
AUTH_PASS = os.environ.get("RECON_PASS", "")  # MUST be set in production

# Hard safety limits (protect the 1 GB VPS from oversized ranges).
MAX_HOSTS = int(_env("RECON_MAX_HOSTS", "65536"))          # /16 worth of IPs
DNS_CONCURRENCY = int(_env("RECON_DNS_CONCURRENCY", "50"))  # fixed worker pool
DNS_TIMEOUT = float(_env("RECON_DNS_TIMEOUT", "3.0"))
DNS_LIFETIME = float(_env("RECON_DNS_LIFETIME", "5.0"))
NAMESERVERS = [s.strip() for s in _env("RECON_NAMESERVERS", "").split(",") if s.strip()]

ENABLE_EXTERNAL_API = _env("RECON_ENABLE_EXTERNAL_API", "false").lower() in ("1", "true", "yes")
EXTERNAL_API_URL = _env(
    "RECON_EXTERNAL_API_URL", "https://api.hackertarget.com/reverseiplookup/?q={ip}"
)
EXTERNAL_API_TIMEOUT = float(_env("RECON_EXTERNAL_API_TIMEOUT", "10.0"))
EXTERNAL_API_CONCURRENCY = int(_env("RECON_EXTERNAL_API_CONCURRENCY", "3"))
# Bounded in-memory cache of external-API results, keyed by IP. Reverse-IP data
# is stable minute-to-minute, so caching lets a repeat scan reuse results
# WITHOUT spending more of the tiny free-tier daily quota. 0 disables it.
EXTERNAL_API_CACHE_MAX = int(_env("RECON_EXTERNAL_API_CACHE_MAX", "2000"))

# API-free reverse-IP discovery (default ON): connect to each IP's TLS port(s)
# and harvest hostnames from the certificate's SAN/CN. Unlike the external API
# this has NO quota and talks ONLY to the target host. Because we send no SNI,
# a shared/SNI host returns just its default cert, so coverage there is partial
# — but everything it finds is real, and it needs no third-party service.
ENABLE_TLS_CERT = _env("RECON_ENABLE_TLS_CERT", "true").lower() in ("1", "true", "yes")
TLS_CERT_PORTS = [int(p) for p in _env("RECON_TLS_CERT_PORTS", "443").split(",")
                  if p.strip().isdigit()]
TLS_CERT_TIMEOUT = float(_env("RECON_TLS_CERT_TIMEOUT", "4.0"))
TLS_CERT_CONCURRENCY = int(_env("RECON_TLS_CERT_CONCURRENCY", str(DNS_CONCURRENCY)))

MAX_INPUT_LEN = 255
MAX_JOBS_RETAINED = 200  # trim the in-memory job table to bound memory

# --------------------------------------------------------------------------- #
# Input validation & hostname hygiene
#
# All target parsing goes through Python's `ipaddress` module and strict
# regexes. We NEVER pass user input to a shell, so command injection is not
# possible; invalid ranges are rejected before any work starts.
# --------------------------------------------------------------------------- #
# RFC-1123 hostname (must be a real FQDN - at least one dot).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def clean_hostname(name: str) -> Optional[str]:
    """Return a normalised hostname, or None if it is not a valid FQDN.

    Guarantees output files contain ONLY valid hostname strings.
    """
    if not name:
        return None
    name = name.strip().rstrip(".").lower()
    if not name or len(name) > 253 or "." not in name:
        return None
    try:  # reject bare IPs masquerading as hostnames
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    return name if _HOSTNAME_RE.match(name) else None


def classify_target(raw: str) -> str:
    """Classify input as 'network', 'ip', or 'domain'; raise ValueError if invalid."""
    raw = (raw or "").strip()
    if not raw or len(raw) > MAX_INPUT_LEN:
        raise ValueError("target is empty or too long")
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return "network"
        except ValueError:
            raise ValueError("invalid CIDR range")
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(raw):
        return "domain"
    raise ValueError("target must be a CIDR range, IP address, or domain name")


def slugify_target(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", raw.strip()).strip("_")[:64] or "target"


def expand_network(raw: str) -> list[str]:
    """Expand a CIDR/IP into host strings, enforcing MAX_HOSTS *before* materialising."""
    net = ipaddress.ip_network(raw, strict=False)
    usable = net.num_addresses if net.num_addresses <= 2 else net.num_addresses - 2
    if usable > MAX_HOSTS:
        raise ValueError(f"range too large: {usable} hosts exceeds limit of {MAX_HOSTS}")
    hosts = list(net) if net.num_addresses <= 2 else list(net.hosts())
    return [str(h) for h in hosts]

# --------------------------------------------------------------------------- #
# DNS / lookup engine
# --------------------------------------------------------------------------- #
def make_resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=not NAMESERVERS)
    if NAMESERVERS:
        r.nameservers = NAMESERVERS
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_LIFETIME
    return r


async def resolve_domain_ips(domain: str, resolver) -> list[str]:
    """Forward-resolve a domain to its A/AAAA addresses (for reverse lookup)."""
    ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            ans = await resolver.resolve(domain, rdtype)
            ips.extend(rr.address for rr in ans)
        except dns.exception.DNSException:
            continue
    return list(dict.fromkeys(ips))


async def ptr_lookup(ip: str, resolver) -> set[str]:
    """Reverse (PTR) lookup for a single IP; failures resolve to an empty set."""
    found: set[str] = set()
    try:
        ans = await resolver.resolve_address(ip)
        for rr in ans:
            h = clean_hostname(str(rr.target))
            if h:
                found.add(h)
    except dns.exception.DNSException:
        pass
    except Exception:
        pass
    return found


# Bounded in-memory cache of external-API results, keyed by IP.
_EXT_CACHE: dict[str, set[str]] = {}


class ExternalRateLimited(Exception):
    """Raised when the third-party reverse-IP API reports its quota is exhausted."""


def _looks_rate_limited(resp) -> bool:
    """Detect a rate-limit / quota response.

    hackertarget (and similar free APIs) return HTTP 200 with a plain-text body
    like 'API count exceeded - Increase Your Query Limits with a Membership: ...'
    once the ~50-lookups/day free quota is spent; some return HTTP 429.
    """
    if resp.status_code == 429:
        return True
    if resp.status_code == 200 and "api count exceeded" in resp.text.lower():
        return True
    return False


def _cache_put(ip: str, found: set[str]) -> None:
    """Store a per-IP result, trimming oldest entries (dicts keep insertion order)."""
    if not EXTERNAL_API_CACHE_MAX:
        return
    _EXT_CACHE[ip] = set(found)
    overflow = len(_EXT_CACHE) - EXTERNAL_API_CACHE_MAX
    if overflow > 0:
        for k in list(_EXT_CACHE.keys())[:overflow]:
            _EXT_CACHE.pop(k, None)


async def external_lookup(ip: str, client, sem: asyncio.Semaphore) -> set[str]:
    """Optional shared-hosting lookup via a third-party reverse-IP API.

    Raises ExternalRateLimited when the API signals the quota is exhausted so
    the caller can stop firing further (doomed) requests. Successful results
    are cached per-IP so repeat scans reuse them without spending more quota.
    """
    found: set[str] = set()
    if client is None:
        return found
    if EXTERNAL_API_CACHE_MAX and ip in _EXT_CACHE:
        return set(_EXT_CACHE[ip])  # cache hit: no API call, no quota spent
    url = EXTERNAL_API_URL.format(ip=ip)
    async with sem:
        try:
            resp = await client.get(url)
        except Exception:
            return found  # transient network error: treat as no data (non-fatal)
    if _looks_rate_limited(resp):
        raise ExternalRateLimited()
    if resp.status_code == 200:
        for line in resp.text.splitlines():
            line = line.strip()
            low = line.lower()
            if not line or "error" in low or "api count exceeded" in low:
                continue
            h = clean_hostname(line)
            if h:
                found.add(h)
        _cache_put(ip, found)  # cache even an empty result to avoid re-querying
    return found

# --------------------------------------------------------------------------- #
# API-free TLS-certificate discovery
#
# Reading the certificate an IP presents is a genuine reverse-IP signal that
# needs no third-party API and no quota: the SAN/CN fields list the hostname(s)
# the server is provisioned for. We connect with NO SNI and NO validation (so
# self-signed / expired certs are still read), then parse the DER ourselves.
# Limitation: on SNI-based shared hosting a bare grab yields only the default
# cert, and CDN/WAF front IPs (e.g. Cloudflare) return an edge cert — partial
# coverage, but every hostname it returns is real.
# --------------------------------------------------------------------------- #
def _names_from_cert_der(der: bytes) -> set[str]:
    """Extract normalised hostnames from a DER-encoded X.509 cert (SAN + CN)."""
    names: set[str] = set()
    if not der or x509 is None:
        return names
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return names
    raw: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        raw.extend(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if isinstance(attr.value, str):
                raw.append(attr.value)
    except Exception:
        pass
    for name in raw:
        if name.startswith("*."):
            name = name[2:]  # wildcard cert -> keep the base domain (a real name)
        h = clean_hostname(name)
        if h:
            names.add(h)
    return names


async def _grab_cert_der(ip: str, port: int, timeout: float) -> Optional[bytes]:
    """Open a TLS connection (no SNI, no verification) and return the peer DER cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=""),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        return ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
    except Exception:
        return None  # closed port / handshake failure / timeout -> no data
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass


async def cert_lookup(ip: str, sem: asyncio.Semaphore) -> set[str]:
    """Harvest hostnames from the TLS cert(s) an IP presents across TLS_CERT_PORTS."""
    found: set[str] = set()
    if x509 is None or not TLS_CERT_PORTS:
        return found
    for port in TLS_CERT_PORTS:
        async with sem:
            der = await _grab_cert_der(ip, port, TLS_CERT_TIMEOUT)
        if der:
            found |= _names_from_cert_der(der)
    return found


# --------------------------------------------------------------------------- #
# Result persistence
# --------------------------------------------------------------------------- #
_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.txt$")


def _safe_filename(name: str) -> str:
    name = os.path.basename(name or "")
    if not _FILENAME_RE.fullmatch(name) or name in (".", ".."):
        raise ValueError("invalid filename")
    return name


def write_results(target: str, results: set[str]) -> str:
    """Write a deduplicated, sorted, header-free hostname list. Returns filename."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = slugify_target(target)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"{slug}_{ts}.txt"
    path = RESULTS_DIR / fname
    ordered = sorted(results)
    tmp = path.with_name(fname + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        if ordered:
            f.write("\n".join(ordered) + "\n")  # ONLY hostnames, one per line
    tmp.replace(path)  # atomic publish
    return fname


# --------------------------------------------------------------------------- #
# Background job model + runner
# --------------------------------------------------------------------------- #
class Job:
    __slots__ = ("id", "target", "kind", "use_external", "status", "total",
                 "processed", "found", "error", "warning", "filename", "created",
                 "started", "finished")

    def __init__(self, job_id: str, target: str, kind: str, use_external: bool):
        self.id = job_id
        self.target = target
        self.kind = kind
        self.use_external = use_external
        self.status = "queued"
        self.total = 0
        self.processed = 0
        self.found = 0
        self.error: Optional[str] = None
        self.warning: Optional[str] = None
        self.filename: Optional[str] = None
        self.created = time.time()
        self.started: Optional[float] = None
        self.finished: Optional[float] = None

    def to_dict(self) -> dict:
        pct = round(self.processed / self.total * 100, 1) if self.total else 0.0
        return {
            "job_id": self.id, "target": self.target, "kind": self.kind,
            "status": self.status, "total": self.total, "processed": self.processed,
            "found": self.found, "progress": pct, "filename": self.filename,
            "error": self.error, "warning": self.warning, "external_api": self.use_external,
            "created": self.created, "started": self.started, "finished": self.finished,
        }


JOBS: dict[str, Job] = {}


def _trim_jobs() -> None:
    if len(JOBS) <= MAX_JOBS_RETAINED:
        return
    finished = sorted((j for j in JOBS.values() if j.finished), key=lambda j: j.finished)
    for j in finished[: len(JOBS) - MAX_JOBS_RETAINED]:
        JOBS.pop(j.id, None)

async def run_scan(job: Job) -> None:
    """Execute a scan using a fixed worker pool so memory stays flat."""
    job.status = "running"
    job.started = time.time()
    resolver = make_resolver()
    client = None
    results: set[str] = set()
    try:
        if job.kind == "network":
            ips = expand_network(job.target)
        elif job.kind == "ip":
            ips = [job.target]
        else:  # domain -> resolve to IPs, then reverse-lookup those IPs
            ips = await resolve_domain_ips(job.target, resolver)
            if not ips:
                raise ValueError("domain did not resolve to any IP address")
        job.total = len(ips)

        if job.use_external and httpx is not None:
            client = httpx.AsyncClient(
                timeout=EXTERNAL_API_TIMEOUT,
                headers={"User-Agent": "recon-reverse-ip/1.0"},
                follow_redirects=True,
            )
        ext_sem = asyncio.Semaphore(EXTERNAL_API_CONCURRENCY)
        cert_sem = asyncio.Semaphore(max(1, TLS_CERT_CONCURRENCY))

        queue: asyncio.Queue[str] = asyncio.Queue()
        for ip in ips:
            queue.put_nowait(ip)

        rate_limited = False  # set once the external API reports quota exhausted

        async def worker() -> None:
            nonlocal rate_limited
            while True:
                try:
                    ip = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    hs = await ptr_lookup(ip, resolver)
                    if job.use_external and client is not None and not rate_limited:
                        try:
                            hs |= await external_lookup(ip, client, ext_sem)
                        except ExternalRateLimited:
                            # Stop hammering a quota that's already exhausted;
                            # remaining IPs still get their PTR lookup below.
                            rate_limited = True
                    if ENABLE_TLS_CERT:
                        # API-free: read the cert straight off the host (no quota).
                        hs |= await cert_lookup(ip, cert_sem)
                    if hs:
                        results.update(hs)
                        job.found = len(results)
                finally:
                    job.processed += 1

        pool = min(DNS_CONCURRENCY, max(1, len(ips)))
        await asyncio.gather(*(worker() for _ in range(pool)))

        if rate_limited:
            job.warning = (
                "External reverse-IP API rate limit reached — the free tier allows "
                "only ~50 lookups/day, so results are incomplete. PTR (DNS) results "
                "are unaffected. Add an API key/membership, scan a smaller range, or "
                "disable the external API for accurate repeat scans."
            )

        job.filename = write_results(job.target, results)
        job.found = len(results)
        job.status = "completed"
    except Exception as exc:  # never let a background task crash silently
        job.status = "failed"
        job.error = str(exc)
    finally:
        if client is not None:
            await client.aclose()
        job.finished = time.time()

# --------------------------------------------------------------------------- #
# Authentication (HTTP Basic, constant-time comparison)
# --------------------------------------------------------------------------- #
security = HTTPBasic(auto_error=True)


def require_auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    if not AUTH_PASS:
        raise HTTPException(status_code=503, detail="Auth not configured: set RECON_PASS")
    user_ok = secrets.compare_digest(creds.username.encode(), AUTH_USER.encode())
    pass_ok = secrets.compare_digest(creds.password.encode(), AUTH_PASS.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=401, detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return creds.username


# --------------------------------------------------------------------------- #
# API models & app
# --------------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=MAX_INPUT_LEN)
    external_api: Optional[bool] = None  # per-scan override of the default

    @field_validator("target")
    @classmethod
    def _valid_target(cls, v: str) -> str:
        v = v.strip()
        classify_target(v)  # raises ValueError -> 422 if invalid
        return v


@asynccontextmanager
async def lifespan(_app: "FastAPI"):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="RECON Reverse IP Lookup",
    version="1.0.0",
    docs_url=None, redoc_url=None, openapi_url=None,  # no public API schema
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

@app.post("/api/scan")
async def start_scan(req: ScanRequest, _user: str = Depends(require_auth)) -> dict:
    kind = classify_target(req.target)
    use_external = ENABLE_EXTERNAL_API if req.external_api is None else bool(req.external_api)
    if use_external and httpx is None:
        use_external = False
    job = Job(secrets.token_hex(8), req.target, kind, use_external)
    JOBS[job.id] = job
    _trim_jobs()
    asyncio.create_task(run_scan(job))
    return job.to_dict()


@app.get("/api/scan/{job_id}")
async def scan_status(job_id: str, _user: str = Depends(require_auth)) -> dict:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job.to_dict()


@app.get("/api/scans")
async def list_scans(_user: str = Depends(require_auth)) -> dict:
    jobs = sorted(JOBS.values(), key=lambda j: j.created, reverse=True)
    return {"jobs": [j.to_dict() for j in jobs]}


@app.get("/api/files")
async def list_files(_user: str = Depends(require_auth)) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    for p in sorted(RESULTS_DIR.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True):
        st = p.stat()
        try:
            with open(p, "rb") as f:
                lines = sum(1 for _ in f)
        except OSError:
            lines = 0
        files.append({
            "name": p.name, "size": st.st_size, "lines": lines,
            "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
        })
    return {"files": files}


@app.get("/api/files/{name}/download")
async def download_file(name: str, _user: str = Depends(require_auth)) -> FileResponse:
    try:
        safe = _safe_filename(name)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid filename")
    path = (RESULTS_DIR / safe).resolve()
    if path.parent != RESULTS_DIR or not path.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(path, media_type="text/plain; charset=utf-8", filename=safe)


@app.delete("/api/files/{name}")
async def delete_file(name: str, _user: str = Depends(require_auth)) -> dict:
    try:
        safe = _safe_filename(name)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid filename")
    path = (RESULTS_DIR / safe).resolve()
    if path.parent != RESULTS_DIR or not path.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    path.unlink()
    return {"deleted": safe}


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    # The shell contains no data; every data/action endpoint above is auth-gated.
    idx = STATIC_DIR / "index.html"
    if idx.is_file():
        return HTMLResponse(idx.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>index.html not found</h1>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=_env("RECON_HOST", "127.0.0.1"),
        port=int(_env("RECON_PORT", "8000")),
        workers=1,
        log_level="info",
    )
