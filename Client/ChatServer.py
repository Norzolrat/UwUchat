import socket
import os
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 1234

# Fonction pour générer une clé AES aléatoire
def generate_aes_key():
    return os.urandom(32)

# Fonction pour chiffrer un message avec une clé AES donnée
def aes_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext

# Fonction pour déchiffrer un message avec une clé AES donnée
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Fonction pour chiffrer une clé AES avec une clé publique RSA donnée
def rsa_encrypt(key, public_key):
    ciphertext = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Fonction pour déchiffrer une clé AES avec une clé privée RSA donnée
def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def main():
    # Création d'une socket TCP/IP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Liaison du socket à l'adresse et au port
        s.bind((SERVER_HOST, SERVER_PORT))

        # Écoute pour les connexions entrantes
        s.listen()

        print(f"Listening on {SERVER_HOST}:{SERVER_PORT}...")

        while True:
            # Attente d'une connexion
            conn, addr = s.accept()
            print(f"Connected by {addr}")

            # Génération d'une paire de clés RSA pour la communication avec le client
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Envoi de la clé publique RSA au client
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(pem)

            # Réception de la clé AES chiffrée avec la clé publique RSA du serveur
            data = conn.recv(1024)
            aes_key = rsa_decrypt(data, private_key)

            while True:
                # Réception de messages chiffrés en AES du client
                data = conn.recv(1024)
                if not data:
                    break
                plaintext = aes_decrypt(data, aes_key)
                print(f"Received message: {plaintext.decode()}")

                # Envoi de réponses chiffrées en AES au client
                message = input("Enter a message: ")
                ciphertext = aes_encrypt(message.encode(), aes_key)
                conn.sendall(ciphertext)

if __name__ == "__main__":
    main()

