import socket
from crypto import (
    load_public_key,
    rsa_encrypt,
    encrypt_aes,
    decrypt_aes,
    generate_aes_key,
    generate_rsa_keys,
    serialize_public_key,
)

IP = '127.0.0.1'
PORT = 5555
ADDR = (IP, PORT)
FORMAT = 'utf-8'

class Client:
    def __init__(self, client_id):
        self.client_id = client_id
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = generate_aes_key()

    def start(self):
        self.client_socket.connect(ADDR)
        server_public_key = load_public_key('server_public_key.pem')

        encrypted_aes_key = rsa_encrypt(server_public_key, self.aes_key)
        self.client_socket.send(encrypted_aes_key)

        public_key, _ = generate_rsa_keys()
        serialized_public_key = serialize_public_key(public_key)

        encrypted_message = encrypt_aes(self.aes_key, f"{self.client_id}:{serialized_public_key}".encode(FORMAT))
        self.client_socket.send(encrypted_message)

        while True:
            target_id = input("Enter target client ID: ")
            if target_id.lower() == 'exit':
                break

            encrypted_target_id = encrypt_aes(self.aes_key, target_id.encode(FORMAT))
            self.client_socket.send(encrypted_target_id)

            encrypted_target_public_key = self.client_socket.recv(4096)
            target_public_key_data = decrypt_aes(self.aes_key, encrypted_target_public_key)

            target_public_key = load_public_key(target_public_key_data)

            message = input("Enter your message: ")

            encrypted_message = rsa_encrypt(target_public_key, message.encode(FORMAT))
            self.client_socket.send(encrypted_message)

        self.client_socket.close()


if __name__ == "__main__":
    client_id = input("Enter your client ID: ")
    client = Client(client_id)
    client.start()
