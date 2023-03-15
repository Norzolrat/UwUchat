#!/usr/bin/python3

import json
import requests
import base64

from mycrypto import *
from common import *

##### CONFIG #####

PROXY = None
# PROXY = {
#   'http': 'http://127.0.0.1:8080',
#   'https': 'http://127.0.0.1:8080',
#}

SERVER_URL = "http://127.0.0.1"

##################

K_S_pub = RSA_import_key("""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvb+UHvJ8zQbSoRZpvZzy
aTLvThvgtwqa5PK4MZP+txB2l5PQdLT1BMkJj/l/In5ajNv/GysXr83vcSMwpG7E
TcGqpLIYisTnYpLDXjJ+DM7RDohoN8YnJrFPGvlFWa8C3R7qSqp+jnMpElS+vCE6
FxklNdlUG7qzFOI5wQDrThGI39wrtEWVKcu5d0MSye6KQqQ46AbdkjuZmp2s5Ryu
7bBeBXLk6rHM2sfZ3jz/Ov109D6J0wlNEoL74GRVgYfuOhnzpoYK9CBokdx8EnSe
PJpg7CAFRvREVKpm1LvL05QN595fiugLEqElhZWzVTfLN1ixAE7h0sDvViSw+6PP
FwIDAQAB
-----END PUBLIC KEY-----
""")


def choices(text, responses_list):
    while True:
        print(text)
        for index, t in enumerate(responses_list):
            print(f"  {index+1} : {t}")

        r = input("Choice > ")
        try:
            r_int = int(r)
            if r_int > 0 and r_int <= len(responses_list):
                return r_int
        except:
            continue

class Client:

    def __init__(self):
        pass

    def send_request(self, params):
        """
        Envoi au serveur un dict python (params) transformé en JSON
        Etablie le canal chiffré (attaquant 1) avec le serveur
        """
        global K_S_pub
        global PROXY
        global SERVER_URL

        request_data = json.dumps(params) # transforme le paramètre en JSON (string)


        r_post = {}

        # FIXME : chiffrer la requête ...
        # r_post["enckey"] = base64.b64encode(...)
        # r_post["IV"] = b64(....)
        # r_post["encdata"] = b64(encrypt(request_data)) # On va chiffrer le JSON

        r_post["encdata"] = request_data # TODO : delete me (Transmis en clair ici)

        r = requests.post(SERVER_URL, data=RSA_encrypt(json.dumps(r_post), K_S_pub), proxies=PROXY)
    
        enc_r = r.text

        # FIXME : dechiffrer la réponse
        # reponse = decrypt(enc_r) ...

        response = enc_r # TODO : delete me (Transmis en clair ici)

        return json.loads(response) # La réponse en clair est du JSON, décodé ici en dict

    def signup(self, user, passwd):
        return self.send_request({"action":"signup", "login":login, "password":passwd})
        # TODO : complet ? .....

    def login(self, user, passwd):
        return self.send_request({"action":"login", "login":login, "password":passwd})

        

c = Client()

r = choices("What to do ?", ["Sign Up", "Log in"])
if r == 1:
    # Sign up
    login = input("Login : ").strip()
    passwd = input("Pasword : ").strip()

    r = c.signup(login, passwd)
    print(r)

else:
    # Log in

    login = input("Login : ").strip()
    passwd = input("Pasword : ").strip()

    r = c.login(login, passwd)
    print(r)

    # recevoir les messages, demander à qui envoyer, etc ....