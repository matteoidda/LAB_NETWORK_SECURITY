import os
import ssl
import json
import uuid
import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie


os.chdir(os.path.dirname(os.path.abspath(__file__)))

SESSIONS = {}

def generate_self_signed_cert():
    if os.path.exists("server.crt") and os.path.exists("server.key"):
        return

    print("[*] Certificate generation....")
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa


    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "server.netsec.lab"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("server.netsec.lab")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open("server.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[+] Certificate generated.")


class Port8443Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

        elif self.path == '/me':
            cookie_header = self.headers.get('Cookie')
            if cookie_header:
                cookie = SimpleCookie()
                cookie.load(cookie_header)
                if 'session_id' in cookie:
                    sid = cookie['session_id'].value
                    if sid in SESSIONS:
                        user = SESSIONS[sid]
                        body = json.dumps({"user": user}).encode('utf-8')
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return

            self.send_response(401)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
                user = data.get("user")
                password = data.get("password")
            except Exception:
                self.send_response(400)
                self.end_headers()
                return

            if user and password == "netsec":
                sid = str(uuid.uuid4())
                SESSIONS[sid] = user
                self.send_response(200)
                self.send_header("Set-Cookie", f"session_id={sid}; Secure; HttpOnly; Path=/")
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


class Port8444Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/whoami':
            peercert = self.connection.getpeercert()
            if not peercert:
                self.send_response(401)
                self.end_headers()
                return

            cn = None
            for rdn in peercert.get('subject', ()):
                for key, value in rdn:
                    if key == 'commonName':
                        cn = value
                        break

            if cn:
                body = cn.encode('utf-8')
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def run_server_8443():
    server = HTTPServer(('0.0.0.0', 8443), Port8443Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("[+] Server TLS (Session) listening on https://0.0.0.0:8443")
    server.serve_forever()


def run_server_8444():
    if not os.path.exists("ca.crt"):
        raise FileNotFoundError("ERROR: 'ca.crt' not found")

    server = HTTPServer(('0.0.0.0', 8444), Port8444Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile="ca.crt")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("[+] Server mTLS listening on https://0.0.0.0:8444")
    server.serve_forever()


if __name__ == '__main__':
    generate_self_signed_cert()

    t1 = threading.Thread(target=run_server_8443, daemon=True)
    t2 = threading.Thread(target=run_server_8444, daemon=True)

    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[*] server shutdown....")