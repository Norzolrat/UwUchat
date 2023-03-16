from utils import *
import json
import base64

public_key = get_rsa_public('public_key.pem')

message = b"Bonjour Bob, c'est Alice !"

aes_key = generate_aes()
aes_key_b64 = base64.b64encode(aes_key)
aes_iv = generate_aes_iv()
aes_iv_b64 = base64.b64encode(aes_iv)
temp_aes = {'aes_key' : aes_key_b64.decode('utf-8'), 'aes_iv' : aes_iv_b64.decode('utf-8')}
temp_aes_json = json.dumps(temp_aes).encode()

enc_message = crypt_message_aes(message, aes_key, aes_iv)


# enc_temp_key = crypt_message_rsa(temp_key_json, public_key)
enc_temp_key = crypt_message_rsa(temp_aes_json, public_key)

data_rsa = {'type' : 'RSA', 'content' : enc_temp_key}
json_data_rsa = base64.b64encode(json.dumps((data_rsa)).encode())
# data_aes = {'type' : 'AES', 'content' : enc_message}
# json_data_aes = base64.b64encode(json.dumps((data_aes)))

print(server_request(json_data_rsa))

# private_key, public_key = generate_rsa_key()
# rsa_key_to_file(private_key, public_key)