import socket
import threading
from crypto import (rsa_decrypt, decrypt_aes, generate_rsa_keys,
                    rsa_encrypt, encrypt_aes, serialize_public_key, load_public_key)


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.server.bind((self.ip, self.port))
        self.server.listen()
        print(f"Server is listening on {self.ip}:{self.port}")

        while True:
            conn, addr = self.server.accept()
            print(f"New connection from {addr}")
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, conn):
        private_key, public_key = generate_rsa_keys()
        serialized_public_key = serialize_public_key(public_key)
        conn.send(serialized_public_key)

        encrypted_aes_key = conn.recv(1024)
        aes_key = rsa_decrypt(encrypted_aes_key, private_key)

        while True:
            encrypted_message = conn.recv(1024)
            iv = conn.recv(1024)
            message = decrypt_aes(encrypted_message, aes_key, iv)
            print(f"Received message: {message}")

            response = input("Enter your response: ")
            encrypted_response, iv = encrypt_aes(response, aes_key)
            conn.send(encrypted_response)
            conn.send(iv)


if __name__ == "__main__":
    server = Server("127.0.0.1", 5555)
    server.start()
