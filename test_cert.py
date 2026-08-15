"""Test for the API-free TLS-certificate reverse-IP path.

Two layers, both fully offline (no external network):
  [A] Unit: parse a hand-built DER cert -> assert SAN + CN extraction,
      wildcard normalisation (*.a.b -> a.b), and rejection of junk names.
  [B] End-to-end: stand up a local asyncio TLS server presenting that cert,
      then drive app.cert_lookup() against it and assert the harvested names.
"""
import asyncio
import datetime
import os
import ssl
import tempfile

os.environ.setdefault("RECON_PASS", "test")
os.environ["RECON_RESULTS_DIR"] = tempfile.mkdtemp(prefix="recon_cert_test_")

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import app

EXPECTED = {"example.com", "www.example.com", "wild.example.org", "cn.example.net"}


def build_self_signed():
    """Self-signed cert: CN=cn.example.net, SAN with a wildcard and a junk name."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cn.example.net")])
    san = x509.SubjectAlternativeName([
        x509.DNSName("example.com"),
        x509.DNSName("www.example.com"),
        x509.DNSName("*.wild.example.org"),  # -> wild.example.org
        x509.DNSName("nodothost"),           # invalid FQDN -> dropped
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


async def run_e2e(cert_pem_path, key_pem_path):
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_pem_path, key_pem_path)

    async def handle(reader, writer):
        try:
            writer.close()
        except Exception:
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    app.TLS_CERT_PORTS = [port]
    app.TLS_CERT_TIMEOUT = 4.0
    try:
        return await app.cert_lookup("127.0.0.1", asyncio.Semaphore(4))
    finally:
        server.close()
        await server.wait_closed()


def main():
    key, cert = build_self_signed()
    der = cert.public_bytes(serialization.Encoding.DER)

    # --- [A] offline DER parse ---
    got = app._names_from_cert_der(der)
    print(f"[A] parsed names: {sorted(got)}")
    assert got == EXPECTED, f"parse mismatch: {sorted(got)} != {sorted(EXPECTED)}"

    # --- [B] live local TLS grab ---
    td = tempfile.mkdtemp(prefix="recon_cert_pem_")
    cert_path = os.path.join(td, "cert.pem")
    key_path = os.path.join(td, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    names = asyncio.run(run_e2e(cert_path, key_path))
    print(f"[B] grabbed names from local TLS server: {sorted(names)}")
    assert names == EXPECTED, f"e2e mismatch: {sorted(names)} != {sorted(EXPECTED)}"

    # --- closed port yields nothing (no crash) ---
    app.TLS_CERT_PORTS = [1]  # nothing listening
    app.TLS_CERT_TIMEOUT = 1.0
    empty = asyncio.run(app.cert_lookup("127.0.0.1", asyncio.Semaphore(4)))
    print(f"[C] closed-port result (expect empty): {sorted(empty)}")
    assert empty == set(), f"closed port should yield nothing, got {empty}"

    print("\nALL ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
