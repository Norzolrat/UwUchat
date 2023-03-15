from http.server import BaseHTTPRequestHandler, HTTPServer
from utils import *

private_key = get_rsa_private('private_key.pem')

import base64

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        encrypted_message_base64 = self.rfile.read(content_length)
        encrypted_message = base64.b64decode(encrypted_message_base64)

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        response = decrypt_message_rsa(encrypted_message, private_key)
        response_content = """{}""".format(response.decode('utf-8'))
        self.wfile.write(response_content.encode('utf-8'))



if __name__ == "__main__":
    HOSTNAME = "localhost"
    SERVER_PORT = 54321
    try:
        webServer = HTTPServer((HOSTNAME, SERVER_PORT), MyServer)
        print("Server started at http://{}:{}".format(HOSTNAME, SERVER_PORT))
        webServer.serve_forever()
    except KeyboardInterrupt:
        print("Keyboard interrupt received, shutting down the server")
    finally:
        webServer.server_close()
        print("Server stopped.")
