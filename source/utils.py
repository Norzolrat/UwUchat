import requests
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def generate_rsa_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open("private_key.pem", "wb") as f:
        f.write(private_key_pem)
    
    public_key_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open("public_key.pem", "wb") as f:
        f.write(public_key_pem)

def get_rsa_private(file):
    with open(file, 'rb') as key_file:
        private_key_pem = key_file.read()
        private_key = load_pem_private_key(private_key_pem, password=None)
        # private_key = private_key_pem
        return private_key
    
def get_rsa_public(file):
    with open(file, 'rb') as key_file:
        public_key_pem = key_file.read()
        # public_key = load_pem_public_key(public_key_pem)
        public_key = public_key_pem
        return public_key

def generate_aes():
    return default_backend().random_bytes(32)

def crypt_message_rsa(message, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_message_rsa(ciphertext, key):
    plaintext = key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def server_request(ask):
    url = 'http://localhost:54321/'
    response = requests.get(url + ask)
    if response.ok:
        return(response.text)