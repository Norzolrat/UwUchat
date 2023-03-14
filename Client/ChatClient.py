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
    # Connexion au serveur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        print("Connected to server")

        # Réception de la clé publique du serveur
        data = s.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            data,
            backend=default_backend()
        )

        # Génération d'une clé AES aléatoire pour le chiffrement des messages
        aes_key = generate_aes_key()

        # Envoi de la clé AES chiffrée avec la clé publique du serveur
        aes_key_ciphertext = rsa_encrypt(aes_key, server_public_key)
        s.sendall(aes_key_ciphertext)

        # Envoi de messages chiffrés en AES au serveur
        while True:
            message = input("Enter message to send: ")
            if message == "quit":
                break
            ciphertext = aes_encrypt(message.encode(), aes_key)
            s.sendall(ciphertext)
            data = s.recv(1024)
            plaintext = aes_decrypt(data, aes_key)
            print("Received data:", plaintext.decode())

    print("Disconnected from server")

if __name__ == '__main__':
    main()
