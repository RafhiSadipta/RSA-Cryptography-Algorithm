import socket
from des_cli import encryption_large_text, decryption_large_text, generate_random_key
from rsa import generate_rsa_keys, rsa_encrypt, rsa_decrypt

def register_public_key(identifier, public_key):
    pka_socket = socket.socket()
    pka_socket.connect(("127.0.0.1", 7000))
    e, n = public_key
    pka_socket.send(f"REGISTER {identifier} {e} {n}".encode())
    response = pka_socket.recv(1024).decode()
    print(response)
    pka_socket.close()

def get_public_key(identifier):
    pka_socket = socket.socket()
    pka_socket.connect(("127.0.0.1", 7000))
    pka_socket.send(f"GET {identifier}".encode())
    response = pka_socket.recv(1024).decode()
    pka_socket.close()
    if response == "Public Key Not Found":
        raise Exception("Public Key Not Found in PKA")
    e, n = map(int, response.split())
    return (e, n)

def client_program():
    host = socket.gethostname()
    port = 5000
    encryption = encryption_large_text
    decryption = decryption_large_text
    randomkey = generate_random_key

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys()
    print("Client RSA Public Key:", public_key)

    # Register public key to PKA
    register_public_key("CLIENT", public_key)

    # Retrieve server public key from PKA
    server_public_key = get_public_key("SERVER")
    print("Server Public Key:", server_public_key)

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Step 1: Generate DES key for client and send it to the server
    client_des_key = randomkey()
    print("Generated DES Key (Client):", client_des_key)

    # Encrypt DES key with RSA (character by character)
    encrypted_client_key = rsa_encrypt(server_public_key, client_des_key)
    client_socket.send(str(encrypted_client_key).encode())
    print("Encrypted DES Key Sent to Server:", encrypted_client_key)

    # Step 2: Receive DES key from server
    encrypted_server_key = eval(client_socket.recv(1024).decode())  # Convert string back to list
    server_des_key = ''.join(rsa_decrypt(private_key, encrypted_server_key))
    print("Encrypted DES Key (Server to Client):", encrypted_server_key)
    print("Decrypted DES Key (Server to Client):", server_des_key)

    while True:
        # Step 3: Send a message to the server
        message = input("Client Message: ")
        if message.lower().strip() == "bye":
            break
        encrypted_message = encryption(message, client_des_key)
        client_socket.send(encrypted_message.encode())
        print("Encrypted Message Sent to Server:", encrypted_message)

        # Step 4: Receive a message from the server
        encrypted_response = client_socket.recv(1024).decode()
        decrypted_response = decryption(encrypted_response, server_des_key)
        print("Encrypted Response (Client):", encrypted_response)
        print("Decrypted Response (Client):", decrypted_response)

    client_socket.close()

if __name__ == '__main__':
    client_program()
