from dataclasses import dataclass
import time
import os
import json
from backend_utils import *

@dataclass
class Token:
    token: str
    time_to_end: str

    def __init__(self, database):
        while True:
            token = os.urandom(16)
            if unicity_token(database, token):
                self.token = token
                break
        self.time = (time.time() + (5 * 3600))

    def get_token(self):
        try:
            if(self.time <= time.time()):
                self.time = (time.time() + (5 * 3600))
                return self.token
            else:
                pass
                #todo delete token
            return None
        except:
            return None
        
    def serialize(self, database):
        try:
            with open(database, 'r') as file:
                json_base = json.loads(file)
            data_user = json.loads("""{
                "token" : %s,
                "time_to_end" : %s
            }
            """%(
                self.token,
                self.time
            ))
            json_base.users.append(data_user)
            with open(database, 'w') as f:
                json.dump(json_base, f)
            return True
        except:
            return False