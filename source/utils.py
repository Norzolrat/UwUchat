import requests
import time
import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# -- Asymetric -- #

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    return private_key, public_key

def rsa_key_to_file(private_key, public_key):
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

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
    return plaintext

# -- symetric -- #

def generate_aes():
    return os.urandom(32)

def generate_aes_iv():
    return os.urandom(32)

def crypt_message_aes(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext

def decrypt_message_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()
    return message

# -- hashing -- #

def password_hash(password, salt):
    try:
        passphrase = password + salt
        hash_object = hashlib.sha256(passphrase.encode())
        hash_hex = hash_object.hexdigest()
        return hash_hex
    except:
        return None

# -- serveur comms -- #

def server_request(encrypted_message_base64):
    url = 'http://localhost:54321/'
    response = requests.post(url, data=encrypted_message_base64)
    if response.ok:
        return(response.text)

# -- persitence -- #

def user_json(username, password, salt):
    user = {username : [password_hash(password, salt), salt]}
    return json.loads(user)

def message_json(content, size):
    user = {size : [time.time(), content]}
    return json.loads(user)

def load_database():
    path = './database.json'
    if not os.path.exists(path):
        data = {'users' : {}, 'messages' : {}}
        file = open(path, 'w+')
        json.dump(data, file)
        file.close
        return (data['users'], data['messages'])
    with open(path, 'r') as file:
        data = json.load(file)
    return (data['users'], data['messages'])

def save_database(users, messages):
    data = {'users' : users, 'messages' : messages}
    path = './database.json'
    file = open(path, 'w+')
    json.dump(data, file)
    file.close

# -- login -- #

