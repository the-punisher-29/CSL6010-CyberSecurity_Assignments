import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from base64 import b64encode

class Client:
    def __init__(self, host='localhost', port=12345):
        """
        Initializes the client with the specified server host and port.
        Sets up the socket and generates RSA keys for secure communication.
        """
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = self.generate_keys()
        self.server_public_key = None

    def generate_keys(self):
        """
        Generates an RSA private-public key pair.
        Returns:
            private_key: The client's private RSA key.
            public_key: The client's public RSA key.
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
        Serializes the client's public key into PEM format for transmission.
        Returns:
            A PEM-encoded byte representation of the client's public key.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt(self, message):
        """
        Encrypts a message using the server's public key.
        Args:
            message: The plaintext message to encrypt.
        Returns:
            Encrypted message as bytes.
        """
        return self.server_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, encrypted_message):
        """
        Decrypts a message using the client's private key.
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

    def start(self):
        """
        Connects to the server, establishes a secure communication channel, 
        exchanges public keys, and allows the user to interact with the server via commands.
        """
        try:
            # Connect to the server
            self.socket.connect((self.host, self.port))
            
            # Step 1: Receive the server's public key and send the client's public key
            server_public_bytes = self.socket.recv(2048)  # Receive server's public key
            self.server_public_key = serialization.load_pem_public_key(
                server_public_bytes,
                backend=default_backend()
            )
            self.socket.send(self.get_public_bytes())  # Send client's public key
            
            print("Secure connection established!")
            
            # Step 2: Command loop for interacting with the server
            while True:
                # Input message from the user
                message = input("Enter command (ECHO:msg/UPPER:msg/REVERSE:msg/EXIT): ")
                if not message:  # Ignore empty inputs
                    continue

                # Encrypt the user's message
                encrypted_data = self.encrypt(message)
                print(f"\nEncrypted message (base64): {b64encode(encrypted_data).decode()}")
                
                # Send the encrypted message to the server
                self.socket.send(encrypted_data)
                
                # Receive and decrypt the server's response
                encrypted_response = self.socket.recv(2048)
                response = self.decrypt(encrypted_response)
                print(f"Encrypted response (base64): {b64encode(encrypted_response).decode()}")
                print(f"Decrypted response: {response}")
                
                # Exit if the user sends an exit command
                if message.lower() == 'exit':
                    break
                    
        except ConnectionRefusedError:
            print("Could not connect to server")  # Server is unavailable
        except Exception as e:
            print(f"Error: {e}")  # Handle other potential errors
        finally:
            # Ensure the socket is closed when finished
            self.socket.close()

if __name__ == "__main__":
    # Create and start the client
    client = Client()
    client.start()
