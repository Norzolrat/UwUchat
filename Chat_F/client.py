import socket
from crypto import (rsa_encrypt, encrypt_aes, generate_aes_key, decrypt_aes,
                    load_public_key)


class Client:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.client.connect((self.ip, self.port))
        serialized_public_key = self.client.recv(1024)
        public_key = load_public_key(serialized_public_key)

        aes_key = generate_aes_key()
        encrypted_aes_key = rsa_encrypt(aes_key, public_key)
        self.client.send(encrypted_aes_key)

        while True:
            message = input("Enter your message: ")
            encrypted_message, iv = encrypt_aes(message, aes_key)
            self.client.send(encrypted_message)
            self.client.send(iv)

            encrypted_response = self.client.recv(1024)
            iv = self.client.recv(1024)
            response = decrypt_aes(encrypted_response, aes_key, iv)
            print(f"Received response: {response}")


if __name__ == "__main__":
    client = Client("127.0.0.1", 5555)
    client.start()
