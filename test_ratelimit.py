"""Repro + regression test for the 'repeat scans return 0' bug.

Simulates the third-party reverse-IP API's free-tier daily quota:
the first few IPs return shared-hosting domains, then the API replies
'API count exceeded'. Verifies the app now (a) surfaces a warning instead
of silently reporting 0, (b) still keeps the results it did get, and
(c) reuses cached per-IP results on a repeat scan without new API calls.
"""
import asyncio
import os
import tempfile

os.environ.setdefault("RECON_PASS", "test")
os.environ["RECON_RESULTS_DIR"] = tempfile.mkdtemp(prefix="recon_test_")

import app


class FakeResp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeClient:
    """Fake httpx client honoring a per-run quota; counts real 'API calls'."""
    def __init__(self, quota, **kwargs):
        self.quota = quota
        self.calls = 0

    async def get(self, url):
        self.calls += 1
        if self.calls > self.quota:
            return FakeResp(200, "API count exceeded - Increase Your Query Limits "
                                 "with a Membership: https://hackertarget.com/ip-tools/")
        # A successful lookup returns a couple of co-hosted domains for this IP.
        ip = url.rsplit("=", 1)[-1]
        tag = ip.replace(".", "-")
        return FakeResp(200, f"host-a-{tag}.example.com\nhost-b-{tag}.example.net\n")

    async def aclose(self):
        pass


def make_client_factory(quota):
    holder = {}
    def factory(**kwargs):
        holder["client"] = FakeClient(quota, **kwargs)
        return holder["client"]
    return factory, holder


async def ptr_none(ip, resolver):
    return set()  # isolate the test to the external-API path (no real DNS)


async def run_once(target, quota):
    factory, holder = make_client_factory(quota)
    app.httpx = type("H", (), {"AsyncClient": staticmethod(factory)})
    app.ptr_lookup = ptr_none
    job = app.Job(app.secrets.token_hex(4), target, "network", use_external=True)
    await app.run_scan(job)
    return job, holder["client"]


def main():
    target = "192.0.2.0/29"  # TEST-NET, 6 usable hosts
    app._EXT_CACHE.clear()

    # --- Scenario A: quota runs out mid-scan (3 of 6 IPs succeed) ---
    job, client = asyncio.run(run_once(target, quota=3))
    assert job.status == "completed", job.status
    assert job.found > 0, "expected non-zero results from the IPs queried before the cap"
    assert job.warning and "rate limit" in job.warning.lower(), \
        f"rate-limit warning not surfaced: {job.warning!r}"
    cached_after_A = len(app._EXT_CACHE)
    print(f"[A] status={job.status} found={job.found} api_calls={client.calls} "
          f"cached_ips={cached_after_A} warning={'YES' if job.warning else 'no'}")
    assert cached_after_A == 3, f"expected 3 cached IPs, got {cached_after_A}"

    # --- Scenario B: repeat scan, API now fully exhausted (quota=0) ---
    job2, client2 = asyncio.run(run_once(target, quota=0))
    print(f"[B] status={job2.status} found={job2.found} api_calls={client2.calls} "
          f"(repeat scan reused cache -> should be NON-ZERO, previously 0)")
    assert job2.found == 6, f"repeat scan should reuse 3 cached IPs x 2 domains = 6, got {job2.found}"
    assert job2.warning, "repeat scan should still warn about the remaining rate-limited IPs"
    # The 3 cached IPs are served locally; among the 3 uncached IPs only the
    # first to reach the API trips the limit, then the short-circuit skips the
    # rest -- so at most 3 (and typically fewer) real API calls are made.
    assert 1 <= client2.calls <= 3, f"expected 1-3 API calls, got {client2.calls}"

    # --- Unit checks on the detector ---
    assert app._looks_rate_limited(FakeResp(429, "")) is True
    assert app._looks_rate_limited(FakeResp(200, "API count exceeded ...")) is True
    assert app._looks_rate_limited(FakeResp(200, "real.example.com")) is False
    print("[C] _looks_rate_limited() detector OK")

    print("\nALL ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
