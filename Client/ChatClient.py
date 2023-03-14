from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

import socket

def send_to_server(encrypted_message, encrypted_aes_key):
    HOST = '127.0.0.1'  # Adresse IP du serveur
    PORT = 65432        # Port utilisé pour la communication
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(encrypted_message + b';' + encrypted_aes_key)


# Message à chiffrer
message = b"Bonjour Bob, c'est Alice !"

# Génération de la clé aléatoire AES
key = Cipher(algorithms.AES.generate_key(), modes.CBC(algorithms.AES.block_size)).encryptor()

# Chiffrement du message en AES
cipher_text = key.update(message) + key.finalize()

# Ouverture de la clé publique du serveur
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

# Génération de la clé aléatoire pour le chiffrement RSA de la clé AES
rsa_key = Cipher(algorithms.AES.generate_key(), modes.CBC(algorithms.AES.block_size)).encryptor()

# Chiffrement de la clé AES en RSA avec la clé publique du serveur
encrypted_aes_key = base64.b64encode(public_key.encrypt(rsa_key.finalize(),
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                     algorithm=hashes.SHA256(),
                                     label=None)))

# Conversion en base64 du message chiffré en AES
encrypted_message = base64.b64encode(cipher_text)

# Envoi du message chiffré en AES et de la clé AES chiffrée en RSA au serveur
send_to_server(encrypted_message, encrypted_aes_key)
