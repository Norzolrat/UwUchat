from utils import *

public_key = get_rsa_public('public_key.pem')

message = b"Bonjour Bob, c'est Alice !"
print(crypt_message_rsa(message, public_key))
# print(server_request(crypt_message_rsa(message, public_key)))

# generate_rsa_key()