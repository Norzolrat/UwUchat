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

req_login = req_for_login(r, public_key)
response = server_request(req_login)



response_ = json.loads(response)
if response_['error'] == 'Sign in Success' or response_['error'] == 'Login Success' :
    print(response_['error'])
    personnal_private_key = response_['private_key']
    while True :
        print("Que faire ?")
        print("  1 : Send")
        print("  2 : Read")
        choice = input("Choix --> ")

        if choice == "1":
            user_r = input("User Receiver : ")
            user_key = req_pub_key_by_user(user_r, public_key)
            data_message = req_send_message(user_key, user_r, login)
            response = server_request(data_message)
        elif choice == "2":
            print('Comming Soon !!!')
        else:
            print("Invalid choice")
            exit()
else :
    print(response_['error'])


# private_key, public_key = generate_rsa_key()
# rsa_key_to_file(private_key, public_key)
