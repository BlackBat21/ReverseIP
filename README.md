# RECON &mdash; Reverse IP Lookup

A lightweight, single-process **FastAPI** service that performs reverse IP lookups
across a **CIDR range**, a **single IP**, or a **domain**. It combines two
**API-free, unlimited** sources — **PTR** (reverse DNS) records and **TLS
certificate** hostnames read straight off each host (SAN/CN) — plus an
**optional** third-party shared-hosting API. Scans run asynchronously in the
background and results are written as flat, deduplicated hostname lists.

Designed to run comfortably on a **1 GB / low-memory Ubuntu VPS**:

- No Redis / Celery / database &mdash; just `asyncio`, an in-memory job table, and flat files.
- Bounded concurrency via a fixed worker pool, so memory stays flat regardless of range size.
- Runs as a hardened, memory-capped (`MemoryMax=250M`) `systemd` service.
- Every data/action endpoint is protected with HTTP Basic Auth.

---

## How it finds hostnames

Each IP is checked against up to three sources; results are merged and deduplicated:

1. **PTR / reverse DNS** — unlimited, no API. Often only one hostname per IP, and
   typically none on CDNs (e.g. Cloudflare), so `0` there can be correct.
2. **TLS certificate (SAN/CN)** — unlimited, no API, **on by default**. Connects to
   the IP's TLS port(s) and reads the hostnames the certificate is issued for,
   surfacing real site names even when PTR is empty. Because no SNI is sent, an
   SNI-based shared host returns only its *default* cert (partial coverage), and
   CDN/WAF IPs return an edge cert — but every name it returns is real.
3. **External shared-hosting API** *(optional, off by default)* — a third-party
   service whose free tier is capped at ~50 lookups/day (see troubleshooting below).

A regression/behaviour test for the TLS-certificate path lives in
[test_cert.py](test_cert.py) (offline DER parse + a live local TLS handshake):

```bash
python test_cert.py
```

---

## One-line install (Ubuntu 24.04 VPS)

Run on a **fresh Ubuntu VPS as root**. The repository is public, so no credentials are needed.

### Public HTTPS deployment (nginx + Let's Encrypt TLS + firewall)

Point your domain's DNS **A record** at the VPS first, then:

```bash
curl -fsSL https://raw.githubusercontent.com/BlackBat21/ReverseIP/main/deploy.sh \
  | sudo bash -s -- --domain recon.example.com --email you@example.com
```

### Loopback-only install (no public exposure)

Installs the service bound to `127.0.0.1:8000` and prints manual TLS steps:

```bash
curl -fsSL https://raw.githubusercontent.com/BlackBat21/ReverseIP/main/deploy.sh | sudo bash
```

The installer generates a random `admin` password and prints it (and the login URL)
in the completion summary.

> **Security note:** HTTP Basic Auth credentials are base64-encoded, **not encrypted**.
> Always terminate TLS in front of the service (the `--domain` mode does this for you)
> before exposing it to the internet.

---

## What the installer does

- Installs system packages (`git`, `python3`, `python3-venv`, `openssl`; plus `nginx`,
  `certbot`, `ufw` in `--domain` mode).
- Clones this repo into `/opt/recon/src` and deploys the app to `/opt/recon`.
- Builds an isolated Python virtualenv and installs pinned dependencies.
- Creates a dedicated, non-login `recon` service user.
- Generates `/opt/recon/.env` with a random password (kept on re-runs).
- Installs and starts a hardened `recon.service` systemd unit.
- In `--domain` mode: configures nginx as a reverse proxy, opens the firewall
  (SSH + HTTP/HTTPS), and provisions a Let's Encrypt certificate with auto-redirect.

### Installer options

```
--domain <d>   Public domain to serve on (enables nginx + TLS)
--email  <e>   Email for Let's Encrypt registration
--repo   <url> Override the source repo (default: this repo)
--branch <b>   Branch to deploy (default: main)
--subdir <p>   Path to app.py inside the repo (default: repo root)
--no-tls       Skip TLS even when a domain is given
```

---

## Manual install (from a clone)

If you'd rather not pipe to `bash`, clone the repo and run the local installer:

```bash
git clone https://github.com/BlackBat21/ReverseIP.git
cd ReverseIP
sudo bash setup.sh
```

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # set RECON_PASS to something non-empty
RECON_PASS=devpassword uvicorn app:app --reload
```

Then open <http://127.0.0.1:8000>.

---

## Configuration

All settings come from environment variables (loaded from `/opt/recon/.env` by the
systemd unit). See [.env.example](.env.example) for the full list. Common ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `RECON_USER` / `RECON_PASS` | `admin` / *(required)* | HTTP Basic Auth credentials |
| `RECON_HOST` / `RECON_PORT` | `127.0.0.1` / `8000` | Bind address / port |
| `RECON_MAX_HOSTS` | `65536` | Hard cap on hosts per scan (protects small VPS) |
| `RECON_DNS_CONCURRENCY` | `50` | Fixed DNS worker-pool size |
| `RECON_NAMESERVERS` | *(system)* | Comma-separated custom resolvers |
| `RECON_ENABLE_TLS_CERT` | `true` | API-free TLS-certificate hostname discovery (per IP) |
| `RECON_TLS_CERT_PORTS` | `443` | Comma-separated TLS ports to probe (e.g. `443,8443,993`) |
| `RECON_ENABLE_EXTERNAL_API` | `false` | Enable third-party shared-hosting fallback |

## Managing the service

```bash
systemctl status recon        # service state
journalctl -u recon -f        # live logs
nano /opt/recon/.env          # change credentials / limits
systemctl restart recon       # apply config changes
```

Scan results are saved to `/var/www/recon/results/*.txt`.

---

## Troubleshooting: "the first scan works, later scans return 0"

This is almost always the **external API** option, not a DNS problem.

- The default external provider (hackertarget) free tier allows only **~50 lookups/day** per source IP. A single `/24` needs 254 lookups, so the first scan drains the quota and every scan after it is rate-limited.
- The app now **detects this and shows a warning** on the scan ("External reverse-IP API rate limit reached …") instead of silently reporting `0`. It also **caches** successful per-IP results, so repeating a scan reuses them without spending more quota, and stops hammering the API once the quota is gone.

What to do:

- For large ranges, **leave "external API" off** — PTR (reverse DNS) is unlimited. Note that some ranges (e.g. Cloudflare `172.67.x` / `104.26.x`) legitimately have no useful PTR records, so `0` there is correct.
- To use the external provider at scale, get a hackertarget membership/API key and point `RECON_EXTERNAL_API_URL` at the keyed endpoint, or scan only a few IPs at a time.

A regression test for this behavior lives in [test_ratelimit.py](test_ratelimit.py):

```bash
python test_ratelimit.py    # simulates the quota; asserts warning + cache reuse
```

---

## Legal

Only run reverse-IP lookups against infrastructure you own or are explicitly
authorized to assess. You are responsible for complying with the terms of any
third-party API you enable and with applicable law.
