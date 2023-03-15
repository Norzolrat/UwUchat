from dataclasses import dataclass
import time
import json
from backend_utils import *

@dataclass
class Message:
    message_id: int
    sender_id: int
    time: str
    content: str

    def __init__(self, users, content, id):
        self.message_id = id
        self.sender_id = users
        self.time = time.time()
        self.content = content

    def get_sender(self):
        try:
            return self.sender_id
        except:
            return None
        
    def get_time(self):
        try:
            return self.time
        except:
            return None
    
    def get_content(self):
        try:
            return self.content
        except:
            return None
    
    def serialize(self, database):
        try:
            with open(database, 'r') as file:
                json_base = json.loads(file)
            data_user = json.loads("""{
                "message_id" : %s,
                "sender_id" : %s,
                "time" : %s,
                "content" : %s
            }
            """%(
                str(self.message_id),
                str(self.sender_id),
                self.time,
                self.content
            ))
            json_base.users.append(data_user)
            with open(database, 'w') as f:
                json.dump(json_base, f)
            return True
        except:
            return False