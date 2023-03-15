from crypto import generate_rsa_keys, serialize_public_key, serialize_private_key

private_key, public_key = generate_rsa_keys()

with open("private_key.pem", "wb") as private_key_file:
    private_key_file.write(serialize_private_key(private_key))

with open("public_key.pem", "wb") as public_key_file:
    public_key_file.write(serialize_public_key(public_key))
