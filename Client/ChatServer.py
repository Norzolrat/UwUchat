import socket
import os
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

HOST = "127.0.0.1"
PORT = 1234

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
    # Chargement de la clé privée RSA du serveur
    with open("server_private_key.pem", "rb") as key_file:
        server_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Création d'une socket TCP/IP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Association de la socket à une adresse IP et un numéro de port
        s.bind((HOST, PORT))

        # Attente de connexion
        s.listen()
        print("Server listening on {}:{}".format(HOST, PORT))

        # Attente de connexion d'un client
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)

            # Envoi de la clé publique RSA du serveur
            server_public_key = server_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(server_public_key)

            # Réception de la clé AES chiffrée avec la clé publique RSA du serveur
            aes_key_ciphertext = conn.recv(1024)
            aes_key = rsa_decrypt(aes_key_ciphertext, server_private_key)

            # Réception de messages chiffrés en AES du client et envoi de réponses chiffrées
            while True:
                data = conn.recv
