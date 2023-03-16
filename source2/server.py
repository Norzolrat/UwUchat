import json
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from utils import *

private_key = get_rsa_private('private_key.pem')
(db_users, db_messages) = load_database()

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        message_base64 = self.rfile.read(content_length)
        print(message_base64)
        POST_data = base64.b64decode(message_base64)
        print(POST_data)
        json_POST = json.loads(POST_data.decode())

        if json_POST['type'] == 'RSA':
            encrypted_message = base64.b64decode(json_POST['content'])
            response = decrypt_message_rsa(encrypted_message, private_key)
        elif json_POST['type'] == 'AES':
            encrypted_message = base64.b64decode(json_POST['content'])
            aes_key, iv_aes_key = ""
            response = decrypt_message_rsa(encrypted_message, aes_key, iv_aes_key)
        else:
            response = "error: Invalid type field"

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
