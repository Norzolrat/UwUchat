import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432  # The port used by the server

# Check if the private and public key files exist. If not, generate new keys.
if not os.path.isfile("private_key.pem") and not os.path.isfile("public_key.pem"):
    print("Generating new key pair...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", "wb") as f:
        f.write(private_key)
    with open("public_key.pem", "wb") as f:
        f.write(public_key)


def rsa_decrypt(ciphertext):
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=padding.SHA256()),
            algorithm=padding.SHA256(),
            label=None
        )
    )
    return plaintext


def aes_decrypt(ciphertext, key):
    # TODO: Implement AES decryption
    pass


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print('Received data:', data)
            rsa_plaintext = rsa_decrypt(data)
            aes_key = rsa_plaintext[:32]
            aes_ciphertext = rsa_plaintext[32:]
            aes_plaintext = aes_decrypt(aes_ciphertext, aes_key)
            print('Decrypted message:', aes_plaintext.decode())
