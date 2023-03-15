import socket
import threading
import json
from crypto import (
    load_private_key,
    rsa_decrypt,
    encrypt_aes,
    decrypt_aes,
    generate_aes_key,
    serialize_public_key,
    load_public_key,
)

IP = '127.0.0.1'
PORT = 5555
ADDR = (IP, PORT)
FORMAT = 'utf-8'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

client_public_keys = {}
private_key = None

def handle_client(conn, addr):
    global client_public_keys
    print(f"[NEW CONNECTION] {addr} connected.")
    
    # Receive client's public key and store it
    client_id = conn.recv(1024).decode(FORMAT)
    client_public_key_bytes = conn.recv(1024)
    client_public_key = load_public_key(client_public_key_bytes)
    client_public_keys[client_id] = client_public_key

    # Receive encrypted AES key and decrypt it
    encrypted_aes_key = conn.recv(1024)
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)

    while True:
        msg_length = conn.recv(1024).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length)

            # Decrypt the message
            decrypted_msg = decrypt_aes(aes_key, msg)
            print(f"[{addr}] {decrypted_msg}")

            if decrypted_msg == "DISCONNECT":
                break

            # Encrypt the reply
            reply = f"Message received: {decrypted_msg}"
            encrypted_reply = encrypt_aes(aes_key, reply)

            # Send the encrypted reply
            reply_length = len(encrypted_reply)
            conn.send(str(reply_length).encode(FORMAT))
            conn.send(encrypted_reply)

    conn.close()

def start():
    global private_key
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    with open("private_key.pem", "rb") as key_file:
        serialized_private_key = key_file.read()
    private_key = load_private_key(serialized_private_key)
    print("[STARTING] server is starting...")
    start()
