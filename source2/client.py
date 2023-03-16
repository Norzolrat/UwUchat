from utils import *

public_key = get_rsa_public('public_key.pem')

message = b"Bonjour Bob, c'est Alice !"
enc_message = crypt_message_rsa(message, public_key)

data_rsa = {'type': 'RSA', 'content': enc_message}

response = server_request(json.dumps(data_rsa).encode())
print(response)
