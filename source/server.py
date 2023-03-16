import io
import json
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from utils import *


private_key = get_rsa_private('private_key.pem')
(db_users, db_messages) = load_database()

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        global db_users, db_messages

        content_length = int(self.headers.get('Content-Length', 0))
        message_base64 = self.rfile.read(content_length)
        POST_data = io.StringIO(base64.b64decode(message_base64).decode())
        json_POST = json.load(POST_data)

        (db_users,error) = resp_for_login(json_POST, db_users)
        response = error.encode()

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response_content = """{}""".format(response.decode('utf-8'))
        self.wfile.write(response_content.encode('utf-8'))

if __name__ == "__main__":
    HOSTNAME = "localhost"
    SERVER_PORT = 54321
    try:
        webServer = HTTPServer((HOSTNAME, SERVER_PORT), MyServer)
        print("[+] Server {} start".format(HOSTNAME))
        webServer.serve_forever()
    except KeyboardInterrupt:
        print(" Shutting down the server")
    finally:
        save_database(db_users, db_messages)
        webServer.server_close()
        print("Server stopped.")