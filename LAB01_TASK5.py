import os
import time
import socket
import threading
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

STATE = {"token": ""}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/claim':
            body = STATE["token"].encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def run_http():
    server = HTTPServer(('0.0.0.0', 8090), Handler)
    server.serve_forever()


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    tor_dir = os.path.abspath("tor_service")
    os.makedirs(tor_dir, exist_ok=True)

    auth_dir = os.path.join(tor_dir, "authorized_clients")
    os.makedirs(auth_dir, exist_ok=True)


    if os.path.exists("netsec.auth"):
        with open("netsec.auth", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()


        auth_file_path = os.path.join(auth_dir, "netsec.auth")
        with open(auth_file_path, "w", encoding="utf-8") as f:
            f.write(content + "\n")

    def find_free_port():
        s = socket.socket()
        s.bind(('', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    app_port = find_free_port()

    def run_app():
        class OnionHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"OK")
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if self.path == '/claim':
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    STATE["token"] = body
                    self.send_response(200)
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

        server = HTTPServer(('127.0.0.1', app_port), OnionHandler)
        server.serve_forever()

    threading.Thread(target=run_app, daemon=True).start()
    threading.Thread(target=run_http, daemon=True).start()

    torrc_path = os.path.join(tor_dir, "torrc")
    with open(torrc_path, "w", encoding="utf-8") as f:
        f.write(f"HiddenServiceDir {tor_dir.replace(os.sep, '/')}\n")
        f.write(f"HiddenServicePort 80 127.0.0.1:{app_port}\n")
        f.write(f"HiddenServiceAuthorizeClient stealth netsec\n")


    tor_path = "C:\\Users\\matte\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"
    if not os.path.exists(tor_path):
        tor_path = "tor"

    subprocess.Popen([tor_path, "-f", torrc_path])

    print("[*] Tor started. Waiting for .onion address...")
    hostname_path = os.path.join(tor_dir, "hostname")
    while not os.path.exists(hostname_path):
        time.sleep(1)

    with open(hostname_path, "r", encoding="utf-8") as f:
        address = f.read().strip().split()[0]

    print(f"\n[+] ONION ADDRESS: {address}\n")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
