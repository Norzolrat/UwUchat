from dataclasses import dataclass
from typing import List
import json
from backend_utils import *

@dataclass
class Group:
    group_id: int
    aes_key: str
    list_users: List[int]
    list_messages: List[int]

    def __init__(self, aes_key, users, id):
        self.group_id = id
        self.aes_key = aes_key
        self.list_users = users
        self.list_messages = []

    def new_message(self, msg):
        try:
            self.list_messages.append(msg)
            return True
        except:
            return False
        
    def get_message_by_indice(self, indice):
        try:
            return self.list_messages[indice]
        except:
            return None

    def send_aes_key(self, send):
        try:
            for user in self.list_users:
                send(user, self.aes_key)
            return True
        except:
            return False

    def add_user(self, user):
        try:
            self.list_users.append(user)
            return True
        except:
            return False
        
    def serialize(self, database):
        try:
            with open(database, 'r') as file:
                json_base = json.loads(file)
            data_user = json.loads("""{
                "group_id" : %s,
                "aes_key" : %s,
                "list_users" : %s,
                "list_messages" : %s
            }
            """%(
                str(self.group_id),
                self.aes_key,
                str(self.list_users),
                str(self.list_messages)
            ))
            json_base.users.append(data_user)
            with open(database, 'w') as f:
                json.dump(json_base, f)
            return True
        except:
            return False