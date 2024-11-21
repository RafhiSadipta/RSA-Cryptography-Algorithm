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

def server_program():
    host = socket.gethostname()
    port = 5000
    encryption = encryption_large_text
    decryption = decryption_large_text
    randomkey = generate_random_key

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys()
    print("Server RSA Public Key:", public_key)

    # Register public key to PKA
    register_public_key("SERVER", public_key)

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    conn, address = server_socket.accept()
    print("Connection from:", address)

    # Retrieve client public key from PKA
    client_public_key = get_public_key("CLIENT")
    print("Client Public Key:", client_public_key)

    # Step 1: Receive DES key from client
    encrypted_client_key = eval(conn.recv(1024).decode())  # Convert string back to list
    client_des_key = ''.join(rsa_decrypt(private_key, encrypted_client_key))
    print("Encrypted DES Key (Client to Server):", encrypted_client_key)
    print("Decrypted DES Key (Client to Server):", client_des_key)

    # Step 2: Generate DES key for server and send it to the client
    server_des_key = randomkey()
    print("Generated DES Key (Server):", server_des_key)

    # Encrypt DES key with RSA (character by character)
    encrypted_server_key = rsa_encrypt(client_public_key, server_des_key)
    conn.send(str(encrypted_server_key).encode())
    print("Encrypted DES Key Sent to Client:", encrypted_server_key)

    while True:
        # Step 3: Receive a message from the client
        encrypted_message = conn.recv(1024).decode()
        if not encrypted_message:
            break
        decrypted_message = decryption(encrypted_message, client_des_key)
        print("Encrypted Message (Server):", encrypted_message)
        print("Decrypted Message (Server):", decrypted_message)

        # Step 4: Send a response to the client
        response = input("Server Response: ")
        if response.lower().strip() == "bye":
            break
        encrypted_response = encryption(response, server_des_key)
        conn.send(encrypted_response.encode())
        print("Encrypted Response Sent to Client:", encrypted_response)

    conn.close()

if __name__ == '__main__':
    server_program()
