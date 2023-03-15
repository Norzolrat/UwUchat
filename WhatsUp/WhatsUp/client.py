import requests
import json
import base64
from mycrypto import RSA_encrypt, AES_encrypt, AES_decrypt, AES_gen_key

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.session = requests.Session()

    def send_request(self, data):
        # Récupérer la clé publique du serveur
        r_get = self.session.get(f"http://{self.host}:{self.port}/getkey")
        K_S_pub_pem = r_get.text

        # Chiffrer les données avec AES, puis chiffrer la clé AES et l'IV avec RSA
        request_data = json.dumps(data)
        enc_key, enc_key_encrypted, enc_iv = RSA_encrypt(K_S_pub_pem, AES_gen_key())

        r_post = {}
        r_post["enckey"] = base64.b64encode(enc_key_encrypted).decode()
        r_post["enciv"] = base64.b64encode(enc_iv).decode()
        r_post["encdata"] = base64.b64encode(AES_encrypt(request_data.encode(), enc_key, enc_iv)).decode()

        # Envoyer la requête chiffrée
        r_post = self.session.post(f"http://{self.host}:{self.port}/postdata", data=r_post)

        # Déchiffrer la réponse
        enc_response = base64.b64decode(r_post.text.encode())
        response_data = AES_decrypt(enc_response, enc_key, enc_iv)

        return json.loads(response_data)

    def signup(self, login, passwd):
        return self.send_request({"action":"signup", "login":login, "password":passwd})

    def login(self, login, passwd):
        return self.send_request({"action":"login", "login":login, "password":passwd})

if __name__ == "__main__":
    host = "localhost"
    port = 80

    c = Client(host, port)

    print("What to do ?")
    print("  1 : Sign Up")
    print("  2 : Log in")
    choice = input("Choice > ")

    if choice == "1":
        login = input("Login : ")
        passwd = input("Password : ")
        r = c.signup(login, passwd)
    elif choice == "2":
        login = input("Login : ")
        passwd = input("Password : ")
        r = c.login(login, passwd)
    else:
        print("Invalid choice")
        exit()

    print(r)
