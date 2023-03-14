import socket
import os
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 1234

def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def main():
    # Génération d'une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Enregistrement de la clé publique dans un fichier pem
    with open("key_public.pem", "wb") as f:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(pem)

    # Création de la clé de chiffrement AES
    key = os.urandom(32)

    # Démarrage du serveur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        print("Server is listening on {}:{}".format(SERVER_HOST, SERVER_PORT))

        # Attente d'une connexion client
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)

            # Envoi de la clé publique du serveur
            with open("key_public.pem", "rb") as f:
                data = f.read()
            conn.sendall(data)

            # Réception de la clé temporaire du client
            data = conn.recv(1024)
            client_key = rsa_decrypt(data, private_key)

            # Envoi de la clé de chiffrement AES chiffrée au client
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(client_key.encode()) + encryptor.finalize()
            conn.sendall(ciphertext)

            # Réception de messages chiffrés du client
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                decryptor = cipher.decryptor()
                client_message = decryptor.update(data) + decryptor.finalize()
                print("Received data:", client_message.decode())

                # Envoi de messages chiffrés au client
                message = input("Enter message to send: ")
                if message == "quit":
                    break
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
                conn.sendall(ciphertext)

    # Suppression de la clé publique du fichier pem
    os.remove("key_public.pem")
    print("Disconnected from client")

