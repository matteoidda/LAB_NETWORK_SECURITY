import socket
import threading

HOST = "0.0.0.0"
PORT = 9001

store = {}
store_lock = threading.Lock()


def handle_command(line):
    if line == "PING":
        return "PONG"

    cmd = line.split(" ", 1)[0]

    if cmd == "ECHO":
        parts = line.split(" ", 1)
        if len(parts) < 2:
            return "ERR"
        return parts[1]

    if cmd == "SET":
        parts = line.split(" ", 2)
        if len(parts) < 3 or parts[1] == "" or parts[2] == "":
            return "ERR"
        with store_lock:
            store[parts[1]] = parts[2]
        return "OK"

    if cmd == "GET":
        parts = line.split(" ", 1)
        if len(parts) < 2 or parts[1] == "":
            return "ERR"
        with store_lock:
            return store.get(parts[1], "NOT_FOUND")

    return "ERR"


def handle_client(conn, addr):
    print(f"[+] Connesso: {addr}")
    buffer = b""
    with conn:
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    line = raw.decode("ascii", errors="replace").rstrip("\r")
                    response = handle_command(line)
                    conn.sendall((response + "\n").encode("ascii", errors="replace"))
        except (ConnectionError, OSError):
            pass
    print(f"[-] Disconnesso: {addr}")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen()
    print(f"Server in ascolto su {HOST}:{PORT}")
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nChiusura server")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
