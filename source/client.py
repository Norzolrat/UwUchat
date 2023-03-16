from utils import *
import json
import base64

public_key = get_rsa_public('public_key.pem')

print("Que faire ?")
print("  1 : Sign Up")
print("  2 : Login")
choice = input("Choix --> ")

if choice == "1":
    login = input("Login : ")
    passwd = input("Password : ")
    r = client_signup(login, passwd)
elif choice == "2":
    login = input("Login : ")
    passwd = input("Password : ")
    r = client_login(login, passwd)
else:
    print("Invalid choice")
    exit()

response = server_request(req_for_login(r, public_key))
print(response)

# private_key, public_key = generate_rsa_key()
# rsa_key_to_file(private_key, public_key)
