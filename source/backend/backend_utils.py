import os
import json
import random
import hashlib
import Token
import User

# ------ # unicity token # ------ #

def unicity_token(database, token):
    try:
        with open(database, 'r') as file:
            json_base = json.loads(file)
        for thetoken in json_base.tokens:
            if thetoken['token'] == token:
                return False
        return True
    except:
        return True

# ------ # unicity + create id user/group/message # ------ #

def unicity_user(database, id):
    try:
        with open(database, 'r') as file:
            json_base = json.loads(file)
        for user in json_base.users:
            if user['user_id'] == id:
                return False
        return True
    except:
        return True

def create_id_user(database):
    try:
        while True:
            id = random.randint(1, 50000)
            if unicity_user(database, id):
                return id
    except:
        return None

def unicity_group(database, id):
    try:
        with open(database, 'r') as file:
            json_base = json.loads(file)
        for group in json_base.groups:
            if group['group_id'] == id:
                return False
        return True
    except:
        return True

def create_id_group(database):
    try:
        while True:
            id = random.randint(1, 50000)
            if unicity_group(database, id):
                return id
    except:
        return None

def unicity_message(database, id):
    try:
        with open(database, 'r') as file:
            json_base = json.loads(file)
        for message in json_base.messages:
            if message['message_id'] == id:
                return False
        return True
    except:
        return True
    
def create_id_message(database):
    try:
        while True:
            id = random.randint(1, 50000)
            if unicity_message(database, id):
                return id
    except:
        return None

def password_hash(password, salt):
    try:
        passphrase = password + salt
        hash_object = hashlib.sha256(passphrase.encode())
        hash_hex = hash_object.hexdigest()
        return hash_hex
    except:
        return None

def login(database, username, password):
    try:
        with open(database, 'r') as file:
            json_base = json.loads(file)
        for user in json_base.users:
            if user['user_name'] == username:
                for thepass in json_base.passwords:
                    if thepass['user_id'] == user['user_id']:
                        if password_hash(password, thepass['salt']) == thepass['hash']:
                            token = Token()
                            token.serialize(database)
                            return token.get_token()
        return None
    except:
        return None

def register(database, username, password, private_key, public_key):
    try:
        user = User(username, private_key, public_key, create_id_user(database))
        salt = os.urandom(16)
        user.serialize(database, password_hash(password, salt), salt)
        return login(database, username, password)
    except:
        return None