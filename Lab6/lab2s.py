import socket
import threading
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

class Server:
    def __init__(self, host='localhost', port=12345):
        """
        Initializes the server with the specified host and port.
        Sets up the socket and generates RSA keys for encryption/decryption.
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.private_key, self.public_key = self.generate_keys()

    def generate_keys(self):
        """
        Generates an RSA private-public key pair.
        Returns:
            private_key: The server's private RSA key.
            public_key: The server's public RSA key.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def get_public_bytes(self):
        """
        Serializes the server's public key into PEM format for transmission.
        Returns:
            A PEM-encoded byte representation of the server's public key.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt(self, message, client_public_key):
        """
        Encrypts a message using the client's public key.
        Args:
            message: The plaintext message to encrypt.
            client_public_key: The public key of the client.
        Returns:
            Encrypted message as bytes.
        """
        return client_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, encrypted_message):
        """
        Decrypts a message using the server's private key.
        Args:
            encrypted_message: The encrypted message to decrypt.
        Returns:
            Decrypted plaintext as a string.
        """
        return self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

    def handle_client(self, client_socket, address):
        """
        Handles communication with a connected client.
        This includes exchanging public keys, processing commands, and sending responses.
        Args:
            client_socket: The socket for communication with the client.
            address: The client's address information.
        """
        try:
            # Step 1: Exchange public keys with the client.
            client_socket.send(self.get_public_bytes())  # Send the server's public key.
            client_public_bytes = client_socket.recv(2048)  # Receive the client's public key.
            client_public_key = serialization.load_pem_public_key(
                client_public_bytes,
                backend=default_backend()
            )
            
            while True:
                # Step 2: Receive encrypted data from the client.
                encrypted_data = client_socket.recv(2048)
                if not encrypted_data:  # If no data is received, the client disconnected.
                    break

                # Step 3: Decrypt the received data.
                data = self.decrypt(encrypted_data)

                # Step 4: Handle special commands like 'exit'.
                if data.lower() == 'exit':
                    response = "Goodbye!"
                    encrypted_response = self.encrypt(response, client_public_key)
                    client_socket.send(encrypted_response)
                    break

                # Step 5: Process other commands.
                command = data.split(':', 1)[0] if ':' in data else data
                message = data.split(':', 1)[1] if ':' in data else ''

                if command == 'ECHO':
                    response = message  # Echo the message back.
                elif command == 'UPPER':
                    response = message.upper()  # Convert the message to uppercase.
                elif command == 'REVERSE':
                    response = message[::-1]  # Reverse the message.
                else:
                    response = "Unknown command"  # Default response for unknown commands.

                # Step 6: Encrypt the response and send it to the client.
                encrypted_response = self.encrypt(response, client_public_key)
                client_socket.send(encrypted_response)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            # Close the connection when done.
            client_socket.close()
            print(f"Connection closed from {address}")

    def start(self):
        """
        Starts the server and listens for incoming client connections.
        Spawns a new thread for each connected client to handle them concurrently.
        """
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Allow up to 5 queued connections.
        print(f"Server listening on {self.host}:{self.port}")

        try:
            while True:
                # Accept incoming client connections.
                client_socket, address = self.server_socket.accept()
                print(f"Connection established with {address}")
                
                # Start a new thread to handle the client.
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True  # Ensure threads close with the main program.
                client_thread.start()
        except KeyboardInterrupt:
            # Gracefully shut down the server on interrupt.
            print("\nShutting down server...")
        finally:
            self.server_socket.close()  # Ensure the socket is closed.

if __name__ == "__main__":
    server = Server()
    server.start()
