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
    print("\n")

    client_socket = socket.socket()
    client_socket.connect((host, port))

    while True:
        # Step 1: Generate a new DES key for the message
        message_des_key = randomkey()
        print("Generated DES Key for Message:", message_des_key)
        # Encrypt the DES key with the server's public key
        encrypted_des_key = rsa_encrypt(server_public_key, message_des_key)
        print("Encrypted DES Key for Message:", encrypted_des_key)

        # Input the message and encrypt it with the DES key
        message = input("Client Message: ")
        if message.lower().strip() == "bye":
            break
        encrypted_message = encryption(message, message_des_key)

        # Send the encrypted DES key and message to the server
        client_socket.send(f"{encrypted_des_key}|{encrypted_message}".encode())
        print("Encrypted Message:", encrypted_message)
        print("\n")

        # Step 2: Receive encrypted DES key and response from the server
        response_data = client_socket.recv(1024).decode()
        encrypted_response_key, encrypted_response_message = response_data.split('|')

        # Decrypt the DES key for the response
        response_des_key = rsa_decrypt(private_key, eval(encrypted_response_key))
        print("Decrypted DES Key for Response:", response_des_key)

        # Decrypt the response using the decrypted DES key
        decrypted_response = decryption(encrypted_response_message, response_des_key)
        print("Encrypted Server Response:", encrypted_response_message)
        print("Decrypted Server Response:", decrypted_response)
        print("\n") 

    client_socket.close()

if __name__ == '__main__':
    client_program()
