import io
import json
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from utils import *

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):

        temp_aes_key = None
        temp_aes_iv = None

        content_length = int(self.headers.get('Content-Length', 0))
        message_base64 = self.rfile.read(content_length)
        POST_data = io.StringIO(base64.b64decode(message_base64).decode())
        json_POST = json.load(POST_data)

        if json_POST['type'] == 'RSA':
            encrypted_message = base64.b64decode(json_POST['content'])
            post_aes = decrypt_message_rsa(encrypted_message, private_key)
            json_aes = json.load(io.StringIO(post_aes.decode('utf-8')))
            MyServer.temp_aes_key = base64.b64decode(json_aes['aes_key'])
            MyServer.temp_aes_iv = base64.b64decode(json_aes['aes_iv'])
            response = b'ok aes key send'
        elif json_POST['type'] == 'AES':
            encrypted_message = base64.b64decode(json_POST['content'])
            aes_key, iv_aes_key = MyServer.temp_aes_key, MyServer.temp_aes_iv
            response = decrypt_message_aes(encrypted_message, aes_key, iv_aes_key)
        else:
            response = b"error: Invalid type field"

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response_content = """{}""".format(response.decode('utf-8'))
        self.wfile.write(response_content.encode('utf-8'))

if __name__ == "__main__":
    private_key = get_rsa_private('private_key.pem')
    (db_users, db_messages) = load_database()
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
