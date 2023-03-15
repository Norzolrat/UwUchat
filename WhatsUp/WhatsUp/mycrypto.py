import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def AES_gen_key():
    return os.urandom(32)

def AES_encrypt(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def AES_decrypt(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def RSA_encrypt(public_key_pem, data):
    public_key_bytes = base64.b64decode(public_key_pem)

    # Debugging statements
    print("Public key data:", public_key_bytes)
    print("Public key data type:", type(public_key_bytes))

    public_key = load_rsa_public_key(public_key_bytes.encode())
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def RSA_decrypt(private_key_pem, data):
    private_key_bytes = base64.b64decode(private_key_pem)
    private_key = load_rsa_private_key(private_key_bytes)
    decrypted_data = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

def load_rsa_private_key(private_key_bytes):
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key

def load_rsa_public_key(public_key_bytes):
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return public_key

def RSA_import_key(key_pem):
    key_bytes = base64.b64decode(key_pem)
    key = load_rsa_private_key(key_bytes)
    return key

