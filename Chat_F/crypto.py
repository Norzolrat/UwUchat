import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import padding as crypto_padding

def pkcs7_pad(data, block_size=16):
    padder = crypto_padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def pkcs7_unpad(padded_data, block_size=16):
    unpadder = crypto_padding.PKCS7(block_size * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(message, public_key):
    cipher_text = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text


def rsa_decrypt(cipher_text, private_key):
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text


def encrypt_aes(plain_text, key):
    padded_plain_text = pkcs7_pad(plain_text.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_plain_text) + encryptor.finalize()
    return cipher_text, iv

def decrypt_aes(cipher_text, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    plain_text = pkcs7_unpad(padded_plain_text)
    return plain_text.decode()


def generate_aes_key():
    return os.urandom(32)


def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def load_public_key(pem):
    public_key = serialization.load_pem_public_key(
        pem, backend=default_backend()
    )
    return public_key


def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem


def load_private_key(pem):
    private_key = serialization.load_pem_private_key(
        pem, password=None, backend=default_backend()
    )
    return private_key

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_private_key(serialized_private_key):
    return serialization.load_pem_private_key(
        serialized_private_key,
        password=None,
        backend=default_backend()
    )

