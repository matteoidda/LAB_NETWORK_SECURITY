import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST = "0.0.0.0"
PORT = 8080


dictionary = {}
dictionary_management = threading.Lock()
next_id = 1



class Management(BaseHTTPRequestHandler):
    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_no_content(self):
        self.send_response(204)
        self.end_headers()

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def route(self, method):
        url = urlparse(self.path)
        path = url.path

        if path == "/":
            if method != "GET":
                return self.send_json(405, {"error": "method not allowed"}, {"Allow": "GET"})
            return self.send_json(200, {"status": "ok"})

        if path == "/echo":
            if method != "GET":
                return self.send_json(405, {"error": "method not allowed"}, {"Allow": "GET"})
            params = parse_qs(url.query, keep_blank_values=True)
            if "msg" not in params:
                return self.send_json(400, {"error": "missing msg"})
            return self.send_json(200, {"msg": params["msg"][0]})

        if path == "/notes":
            if method != "POST":
                return self.send_json(405, {"error": "method not allowed"}, {"Allow": "POST"})
            return self.create_note()

        if path.startswith("/notes/"):
            if method not in ("GET", "DELETE"):
                return self.send_json(405, {"error": "method not allowed"}, {"Allow": "GET, DELETE"})
            raw_id = path[len("/notes/"):]
            if not (raw_id.isascii() and raw_id.isdigit()):
                return self.send_json(404, {"error": "not found"})
            note_id = int(raw_id)
            if method == "GET":
                return self.get_note(note_id)
            return self.delete_note(note_id)

        return self.send_json(404, {"error": "not found"})

    def create_note(self):
        global next_id
        body = self.read_body()

        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";")[0].strip().lower() != "application/json":
            return self.send_json(415, {"error": "unsupported media type"})

        try:
            data = json.loads(body)
        except ValueError:
            return self.send_json(400, {"error": "malformed json"})

        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            return self.send_json(400, {"error": "text must be a string"})

        with dictionary_management:
            note_id = next_id
            next_id += 1
            dictionary[note_id] = data["text"]
        return self.send_json(201, {"id": note_id})

    def get_note(self, note_id):
        with dictionary_management:
            text = dictionary.get(note_id)
        if text is None:
            return self.send_json(404, {"error": "not found"})
        return self.send_json(200, {"id": note_id, "text": text})

    def delete_note(self, note_id):
        with dictionary_management:
            existed = dictionary.pop(note_id, None) is not None
        if not existed:
            return self.send_json(404, {"error": "not found"})
        return self.send_no_content()

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_PATCH(self):
        self.route("PATCH")

    def do_DELETE(self):
        self.route("DELETE")


def main():
    server = ThreadingHTTPServer((HOST, PORT), Management)
    print(f"Server HTTP in ascolto su {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nChiusura server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
