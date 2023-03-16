from utils import *

public_key = get_rsa_public('public_key.pem')

message = b"Bonjour Bob, c'est Alice !"
# temp_aes_key = generate_aes()
# temp_aes_key_iv = generate_aes_iv()
# enc_message = crypt_message_aes(message, temp_aes_key, temp_aes_key_iv)
# enc_temp_key = crypt_message_rsa(str([temp_aes_key, temp_aes_key_iv]), public_key)
enc_temp_key = crypt_message_rsa(message, public_key)

data_rsa = {'type' : 'RSAs', 'content' : enc_temp_key}
# data_aes = {'type' : 'AES', 'content' : enc_message}

print(server_request(data_rsa))

# private_key, public_key = generate_rsa_key()
# rsa_key_to_file(private_key, public_key)