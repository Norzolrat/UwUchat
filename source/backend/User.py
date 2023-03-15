from dataclasses import dataclass
import os
import json
from backend_utils import *

@dataclass
class User:
    user_id: int
    user_name: str
    private_key: str
    public_key: str

    def __init__(self, user_name, private_key, public_key, id):
        self.user_id = id
        self.user_name = user_name
        self.private_key = private_key
        self.public_key = public_key

    def get_user_name(self):
        try:
            return self.user_name
        except:
            return None
        
    def get_private_key(self):
        try:
            return self.private_key
        except:
            return None
        
    def get_public_key(self):
        try:
            return self.public_key
        except:
            return None
        
    def serialize(self, database, password=None, salt=None):
        try:
            with open(database, 'r') as file:
                json_base = json.loads(file)
            data_user = json.loads("""{
                "user_id" : %s,
                "user_name" : %s,
                "private_key" : %s,
                "public_key" : %s
            }
            """%(
                str(self.user_id),
                self.user_name,
                self.private_key,
                self.public_key
            ))
            json_base.users.append(data_user)
            if password:
                data_password = json.loads("""{
                    "user_id" : %s,
                    "hash" : %s,
                    "salt" : %s
                }
                """%(
                    str(self.user_id),
                    password,
                    salt,
                ))
                json_base.password.append(data_password)
            with open(database, 'w') as f:
                json.dump(json_base, f)
            return True
        except:
            return False
