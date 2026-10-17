import asyncio
import hashlib
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated

HOST = "0.0.0.0"
PORT = 4433
ALT_SVC = f'h3=":{PORT}"'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "server.crt")
KEY_FILE = os.path.join(BASE_DIR, "server.key")


def route(method, path, body, protocol):
    path = path.split("?", 1)[0]

    if path == "/":
        if method != "GET":
            return 405, "text/plain", b"method not allowed"
        return 200, "text/plain", b"ok"

    if path == "/proto":
        if method != "GET":
            return 405, "text/plain", b"method not allowed"
        return 200, "text/plain", protocol.encode()

    if path == "/hash":
        if method != "POST":
            return 405, "text/plain", b"method not allowed"
        return 200, "text/plain", hashlib.sha256(body).hexdigest().encode()

    return 404, "text/plain", b"not found"


class TLSServer(ThreadingHTTPServer):

    def __init__(self, address, handler, context):
        super().__init__(address, handler)
        self.socket = context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def finish_request(self, request, client_address):
        try:
            request.settimeout(10)
            request.do_handshake()
        except (ssl.SSLError, OSError) as e:
            print(f"[TCP] Handshake failed by {client_address[0]}: {e}")
            return
        super().finish_request(request, client_address)


class TCPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_any(self, method):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""

        status, content_type, data = route(method, self.path, body, self.request_version)

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Alt-Svc", ALT_SVC)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


class H3Protocol(QuicConnectionProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = None
        self.requests = {}

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self.h3 = H3Connection(self._quic)

        if self.h3 is None:
            return

        for h3_event in self.h3.handle_event(event):
            self.h3_event_received(h3_event)

    def h3_event_received(self, event):
        if isinstance(event, HeadersReceived):
            headers = dict(event.headers)
            self.requests[event.stream_id] = {
                "method": headers.get(b":method", b"").decode(),
                "path": headers.get(b":path", b"/").decode(),
                "body": bytearray(),
            }
            if event.stream_ended:
                self.respond(event.stream_id)

        elif isinstance(event, DataReceived):
            request = self.requests.get(event.stream_id)
            if request is None:
                return
            request["body"] += event.data
            if event.stream_ended:
                self.respond(event.stream_id)

    def respond(self, stream_id):
        request = self.requests.pop(stream_id, None)
        if request is None:
            return

        status, content_type, data = route(request["method"], request["path"], bytes(request["body"]), "HTTP/3")

        self.h3.send_headers(stream_id, [
            (b":status", str(status).encode()),
            (b"content-type", content_type.encode()),
            (b"content-length", str(len(data)).encode()),
        ])
        self.h3.send_data(stream_id, data, end_stream=True)
        self.transmit()


def make_tcp_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def make_quic_config():
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(CERT_FILE, KEY_FILE)
    config.max_data = 16 * 1024 * 1024
    config.max_stream_data = 4 * 1024 * 1024
    return config


async def run_quic():
    await serve(HOST, PORT, configuration=make_quic_config(), create_protocol=H3Protocol)
    print(f"HTTP/3 (QUIC) listening on {HOST}:{PORT}/udp")
    await asyncio.Future()


def main():
    tcp_server = TLSServer((HOST, PORT), TCPHandler, make_tcp_context())
    threading.Thread(target=tcp_server.serve_forever, daemon=True).start()
    print(f"HTTPS (TCP) listening on {HOST}:{PORT}/tcp")

    try:
        asyncio.run(run_quic())
    except KeyboardInterrupt:
        print("\nChiusura server")
    finally:
        tcp_server.shutdown()
        tcp_server.server_close()


if __name__ == "__main__":
    main()