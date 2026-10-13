"""Small local webhook receiver for Bridgit demos."""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        print("\n--- BRIDGIT RECORD ---")
        print(body.decode("utf-8", errors="replace"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    print("Bridgit webhook listening at http://127.0.0.1:8080/ingest")
    print("Press Ctrl+C to stop.")
    HTTPServer(("127.0.0.1", 8080), Receiver).serve_forever()
