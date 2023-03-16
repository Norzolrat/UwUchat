import requests
import hashlib
import time
import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import asymmetric


# -- Asymetric -- #

def generate_rsa_key():
    private_key = asymmetric.rsa.generate_private_key(
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
        return private_key
    
def get_rsa_public(file):
    with open(file, 'rb') as key_file:
        public_key_pem = key_file.read()
        public_key = public_key_pem
        return public_key

def crypt_message_rsa(message, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)

    ciphertext = public_key.encrypt(
        message,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_message_rsa(ciphertext, key):
    plaintext = key.decrypt(
        ciphertext,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# -- symetric -- #

def generate_aes():
    return os.urandom(32)

def generate_aes_iv():
    return os.urandom(16)

def crypt_message_aes(message, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()


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

# -- test -- #

if __name__ == "__main__":
    data = b"my super message, hfhfhfhfhfhshshdhsfjjf"

    public_key = get_rsa_public('public_key.pem')
    private_key = get_rsa_private('private_key.pem')

    enc_data = crypt_message_rsa(data, public_key)
    response = decrypt_message_rsa(base64.b64decode(enc_data), private_key)

    print("=----------- RSA ----------=")
    print("=-- - " + response.decode('utf-8') + " - --=")
    print("=--------------------------=")

    temp_aes = {'aes_key' : generate_aes(), 'aes_iv' : generate_aes_iv()}
    enc_data_aes = crypt_message_aes(data, temp_aes['aes_key'], temp_aes['aes_iv'])
    response_aes = decrypt_message_aes(base64.b64decode(enc_data_aes), temp_aes['aes_key'], temp_aes['aes_iv'])

    print("\n=----------- AES ----------=")
    print("=-- - " + response_aes.decode('utf-8') + " - --=")
    print("=--------------------------=")

