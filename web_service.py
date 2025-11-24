#!/usr/bin/env python3
import http.server
import socketserver
import logging
import os
from datetime import datetime

# Configuration
HOST = "127.0.0.1"  # Bind only locally
PORT = 8080         # Change if needed
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))  # Root folder is where the script runs
LOG_FILE = os.path.join(ROOT_DIR, "access.log")


class LocalRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler with logging to file and console."""

    def log_message(self, format, *args):
        # Timestamped message
        message = "%s - - [%s] %s\n" % (
            self.client_address[0],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            format % args,
        )

        # Log to console
        print(message, end="")

        # Log to file
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(message)

    def translate_path(self, path):
        # Restrict to ROOT_DIR (prevents directory traversal)
        local_path = http.server.SimpleHTTPRequestHandler.translate_path(self, path)
        rel_path = os.path.relpath(local_path, os.getcwd())
        safe_path = os.path.join(ROOT_DIR, rel_path)
        return safe_path


def main():
    os.chdir(ROOT_DIR)

    # Create an initial empty log file if it doesn't exist
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("=== Local Web Server Access Log ===\n")

    handler = LocalRequestHandler

    with socketserver.TCPServer((HOST, PORT), handler) as httpd:
        print(f"Serving HTTP on http://{HOST}:{PORT} (root: {ROOT_DIR})")
        print(f"Access log file: {LOG_FILE}")
        print("Press Ctrl+C to stop.\n")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            httpd.server_close()


if __name__ == "__main__":
    main()
