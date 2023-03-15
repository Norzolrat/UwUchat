from http.server import BaseHTTPRequestHandler, HTTPServer
from utils import *

private_key = get_rsa_private('private_key.pem')

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response = decrypt_message_rsa(self.path[1:].encode(), private_key)

        response_content = """{}""".format(response.decode('utf-8'))

        # response_content = """
        # <html>
        #     <head>
        #         <title>UwUchat</title>
        #     </head>
        #     <body>
        #         <p>Request: {}</p>
        #     </body>
        # </html>
        # """.format(self.path)

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
