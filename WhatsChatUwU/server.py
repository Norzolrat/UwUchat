#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import base64

from mycrypto import *
from common import *

# "JSON"  database in memory
BDD = {
    "users":{},
    "messages":[]
} 

K_S_priv = RSA_import_key("""
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9v5Qe8nzNBtKh
Fmm9nPJpMu9OG+C3Cprk8rgxk/63EHaXk9B0tPUEyQmP+X8iflqM2/8bKxevze9x
IzCkbsRNwaqkshiKxOdiksNeMn4MztEOiGg3xicmsU8a+UVZrwLdHupKqn6OcykS
VL68IToXGSU12VQburMU4jnBAOtOEYjf3Cu0RZUpy7l3QxLJ7opCpDjoBt2SO5ma
nazlHK7tsF4FcuTqsczax9nePP86/XT0PonTCU0SgvvgZFWBh+46GfOmhgr0IGiR
3HwSdJ48mmDsIAVG9ERUqmbUu8vTlA3n3l+K6AsSoSWFlbNVN8s3WLEATuHSwO9W
JLD7o88XAgMBAAECggEAGJTakV3JqYf86SMtr1jx6zX5htgZYa0iiY7Lf5oUG/l/
25LUemISVzyHcXBENkmXMntc+P3j/ixYHNiPDdD5u7cKA8xnXdw0u5zsFBEc1Pea
trQY3ZeH7T0i1ImUIJJfH8VIW0RAy/SC+XMiwzLXbd7zO/QmhMcdjxLgTNlxImDt
qj+RfTsiKMKqEawC3zpaFSOflfq0dOwXXjVTU/ermRE/9zZwXpFSn8nRtRfni614
Eop1eDpMqyzvirnkPILoxrFJWUt9vlwvcifWyp8MQAfNHtaJAoNYP+1c6N72AP/g
GPixvVvZRgxJlsJUkbZvRA5ebkw4ObVialtvT9eUEQKBgQDl0b80yV6JkrMJaZts
p5voMYnfeZitvlfIJuFl1Ib1rtifd2j1z0TElhChcg0sRBvWLNfAvohIUMJiNEhY
kT6F2zbzzKF0ZitkhZ4T+kKcVb/NeA+BjE89RSKQAVcanA2No5ex2eAzQBQ5as8a
k7NL+EyItHPIfoMMfJ6ArXoYUQKBgQDTXTyEWqTjj5gBwvby4+Kd+z28kd2uyT6f
skfyswBi3xU5cAUSa6qB7O2mn2hV9aZQDi24s57tkLYM5nyT6QVHiVg4nahz51iu
SKQIRBUI48gfhInFxEXQI8JzVyntwmQ4PzoO7UM+nEtPr9t6PDkhpzH+g9RZXsRF
r/vIkoB+5wKBgQCgHc41nMZ82vRZ7nYW8X+x+jGwvSsegarvDAelxrhwm2zZTXyX
Jd0nidX0ZV3AJYOvaHa5FwYkO//yI7Lz4d3JrL1QhpVGX5iD5IQKLyYRfbywDqHf
BD6A1ZYK9qQVKfxXXk7l3oJRsqdkiYHZZmZY25mW9QJmAZ6UKI7V4AdcwQKBgQCM
lFW83iEPbaE3groHIMTIOKN+OTJNn3I0ezpZVO8r055lPnlRICUfFzuVeC7IBYOh
eVy1nVpWPcqn1+EB65lkVBhGR64TsMqN2KipCsdGy2F+fQO5curQHgil+FJd3c4U
jxEJfoscKI36qUd8DHQfSvn4gywIaPx4MS1w4Ofv/wKBgEx/2TKCwopQfdXvJiUR
OxiZGJcnMWhuFLPhlRT2TukRAhju1KtML5L/M1JxHDL+eLFf871imp5cMWD0AZKg
OXgUBtAHP3hiOwvluG1xu2t+SnCI9jd0KfBTZy1gngXqMU5vlrNi3tS6uSsIWmMT
Jh+8KuImr4GWKYxX58HA6c8x
-----END PRIVATE KEY-----
""")
K_S_pub = K_S_priv.public_key()

class Server(BaseHTTPRequestHandler):
    def do_POST(self):
        global K_S_priv
        global K_S_pub

        content_length = int(self.headers['Content-Length'])
        ENC_POST_data = self.rfile.read(content_length)
        POST_data = RSA_decrypt(ENC_POST_data, K_S_priv)
        json_POST = json.loads(POST_data) # Charge le JSON de la requête

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        response = decrypt_message_rsa(encrypted_message, private_key)
        response_content = """{}""".format(response.decode('utf-8'))
        self.wfile.write(response_content.encode('utf-8'))
        # DONE : déchiffrer la requête
        
        enckey = base64.b64decode(json_POST["enckey"])
        encIV = json_POST["IV"]
        data = b64(decrypt(json_POST["encdata"]))


        data = json_POST["encdata"] # TODO : delete me (Transmis en clair ici)

        decrypted_request = json.loads(data) # Converti le JSON déchiffré en dict python

        response = self.handle_request(decrypted_request)
        json_response = json.dumps(response)

        # TODO : chiffrer la réponse
        # encrypted_json = crypt(json_response) ...

        encrypted_json = json_response # TODO delete me (En clair ici aussi donc)
        
        json_response = json.dumps(encrypted_json)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json_response.encode())


    def handle_request(self, params:dict)->dict:
        """
        Gère une requête JSON recue : paramètres JSON décodés en params
        retourne un dict python (converti en JSON plus tard)
        """
        global BDD

        print("[+] request received : ", params)

        if params["action"] == "signup":
            login = params["login"]
            if login in BDD["users"].keys():
                print(f"[+] User {login} already exists")
                return {"error":"Already exists"}

            BDD["users"][params["login"]] = {
                "password":params["password"] # TODO : ou pas .....
                }

            return {"message":"welcome"}

            # TODO : complet ? ....

        elif params["action"] == "login":
            login = params["login"]
            if login not in BDD["users"].keys():
                return {"error":"Bad login"}
            else:
                if BDD["users"][login]["password"] == params["password"]: # TODO : re "ou pas" ....
                    return {"message":"good login"}
                else:
                    return {"error":"bad password"}
        
        # TODO : le reste ?   
        # elif action == get_message, send_message, etc ....


httpd = HTTPServer(('localhost', 80), Server)
print("[+] Server waiting ...")
httpd.serve_forever()