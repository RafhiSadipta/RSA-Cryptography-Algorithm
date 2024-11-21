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
    print("\n")

    while True:
        # Step 1: Receive encrypted DES key and message from client
        data = conn.recv(1024).decode()
        if not data:
            break
        encrypted_message_key, encrypted_message = data.split('|')

        # Decrypt the DES key for the current message
        message_des_key = rsa_decrypt(private_key, eval(encrypted_message_key))
        print("Decrypted DES Key for Message:", message_des_key)

        # Decrypt the message using the decrypted DES key
        decrypted_message = decryption(encrypted_message, message_des_key)
        print("Encrypted Client Message:", encrypted_message)
        print("Decrypted Client Message:", decrypted_message)
        print("\n")

        # Step 2: Generate a new DES key for the response
        response_des_key = randomkey()
        print("Generated DES Key for Response:", response_des_key)

        # Encrypt the DES key with the client's public key
        encrypted_response_key = rsa_encrypt(client_public_key, response_des_key)

        # Input the response and encrypt using the new DES key
        response = input("Server Response: ")
        if response.lower().strip() == "bye":
            break
        encrypted_response = encryption(response, response_des_key)

        # Send the encrypted DES key and response to the client
        conn.send(f"{encrypted_response_key}|{encrypted_response}".encode())
        print("Encrypted Response:", encrypted_response)
        print("\n")

    conn.close()

if __name__ == '__main__':
    server_program()
