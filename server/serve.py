"""
Embedded HTTPS server that serves the installers/ directory.

If no external --server URL is provided, the tool generates a self-signed
certificate and spins this up so remote hosts can pull installers directly
from the machine running the tool.
"""

import ipaddress
import os
import socket
import ssl
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


INSTALLERS_DIR = Path(__file__).parent.parent / 'installers'


def _local_ip() -> str:
    """Best-guess outbound IP of this machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'


def _generate_self_signed_cert(cert_path: str, key_path: str, ip: str):
    """Generate a self-signed cert/key pair using cryptography or openssl."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ip),
        ])
        san = x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address(ip)),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    except ImportError:
        # Fall back to openssl CLI
        os.system(
            f'openssl req -x509 -newkey rsa:2048 -keyout {key_path} '
            f'-out {cert_path} -days 1 -nodes '
            f'-subj "/CN={ip}" '
            f'-addext "subjectAltName=IP:{ip}" '
            f'2>/dev/null'
        )


class _QuietHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(INSTALLERS_DIR), **kwargs)

    def log_message(self, fmt, *args):
        # Only log requests (skip the noisy default)
        print(f'    [server] {self.address_string()} — {fmt % args}')


def start_embedded_server(port: int = 8443, use_https: bool = True) -> str:
    """
    Start the embedded file server in a daemon thread.
    Returns the base URL that remote hosts should use.
    """
    if not INSTALLERS_DIR.exists():
        INSTALLERS_DIR.mkdir(parents=True)
        print(f'[*] Created installers directory: {INSTALLERS_DIR}')

    ip = _local_ip()
    httpd = ThreadingHTTPServer((ip, port), _QuietHandler)

    if use_https:
        import tempfile
        tmp = tempfile.mkdtemp()
        cert_path = os.path.join(tmp, 'cert.pem')
        key_path = os.path.join(tmp, 'key.pem')
        print(f'[*] Generating self-signed TLS certificate for {ip}...')
        _generate_self_signed_cert(cert_path, key_path, ip)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = 'https'
    else:
        scheme = 'http'

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    url = f'{scheme}://{ip}:{port}'
    print(f'[+] Installer server running at {url}')
    print(f'    Serving from: {INSTALLERS_DIR}')
    return url
