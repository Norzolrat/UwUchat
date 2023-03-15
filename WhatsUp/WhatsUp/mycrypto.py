import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad




### HASH

import hashlib

def hash(data:bytes):
    """
    SHA256(data)
    
    data : bytes
    return : bytes
    """
    h = hashlib.new("sha256")
    h.update(data)
    return h.digest()


### SYMETRIC

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def AES_gen_key() -> bytes:
    """
    Generate AES key
    """
    return os.urandom(32) # /dev/urandom sous linux, CryptGenRandom() sous Windows

def AES_gen_IV() -> bytes:
    """
    Generate AES IV
    """
    return os.urandom(16)

def AES_encrypt(data, key, iv) -> bytes:
    """
    Encrypt data with AES using key and iv
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    enc = encryptor.update(data) + encryptor.finalize()
    return enc

def AES_decrypt(enc, key, iv) -> bytes:
    """
    Decrypt encdata with AES using key and iv
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dec = decryptor.update(enc) + decryptor.finalize()
    return dec

def PBKDF2(password) -> bytes:
    """
    Get an AES key from a password
    """
    # Note : On s'en fiche pour ce projet
    h = password
    for i in range(0, 100):
        h = hash(h)

    return h[:32]


### ASYMETRIC

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def RSA_gen_key() -> tuple:
    """
    Generate RSA key pair
    return (public key, private key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        )

    return (private_key.public_key(), private_key)

def RSA_export_key(key) -> bytes:
    """
    Export RSA key to string (PEM)
    """
    if key.__class__ == _RSAPublicKey:
        # export a public key
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        # export a private key
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
    

def RSA_import_key(pem:bytes):
    """
    Import RSA key from string (PEM)
    """

    if type(pem) == str: # avoid mistakes :)
        pem = pem.encode()

    if pem.find(b'PRIVATE') >= 0:
        return serialization.load_pem_private_key(pem, password=None)
    else:
        return serialization.load_pem_public_key(pem)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def load_rsa_public_key(pem_data):
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key

from cryptography.hazmat.primitives.asymmetric import padding

def RSA_encrypt(public_key_bytes, data):
    public_key = load_rsa_public_key(public_key_bytes.encode())
    
    key = os.urandom(32)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc_data = cipher.encryptor().update(data) + cipher.encryptor().finalize()

    enc_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return enc_key, enc_data, iv



def rsa_public_key_to_pem(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def RSA_decrypt(data, key) -> bytes:
    """
    Pass the RSA decryption algorithm on the data with the key (public or private)
    """
    return key.decrypt(data, padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None)
                )


#
# Pour tester que tout marche bien / example
#

if __name__ == "__main__":
    data = b"my super message"

    K = AES_gen_key()
    IV = AES_gen_IV()

    enc = AES_encrypt(data, K, IV)
    d = AES_decrypt(enc, K, IV)

    print(d)

    (pub, priv) = RSA_gen_key()

    enc = RSA_encrypt(data, pub)
    print(RSA_decrypt(enc, priv))
    
    pub_pem = RSA_export_key(pub)
    priv_pem = RSA_export_key(priv)

    print(pub_pem.decode())
    print(priv_pem.decode())

    pub_loaded = RSA_import_key(pub_pem)
    priv_loaded = RSA_import_key(priv_pem)

    enc = RSA_encrypt(data, pub_loaded)
    print(RSA_decrypt(enc, priv_loaded))

    

