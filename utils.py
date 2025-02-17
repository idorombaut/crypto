import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature


def generate_and_serialize_keys():
    """
    Generates an ECC public-private key pair, serializes them, and returns the serialized keys.

    Returns:
        tuple: A tuple containing:
            - serialized_public_key (str): The public key serialized to a string format.
            - serialized_private_key (str): The private key serialized to a string format.
    """
    private_key, public_key = generate_ec_key_pair()
    serialized_public_key = serialize_public_key(public_key)
    serialized_private_key = serialize_private_key(private_key)
    return serialized_public_key, serialized_private_key


def generate_ec_key_pair():
    """
    Generates an Elliptic Curve (EC) key pair using SECP256R1 curve.
    
    Returns:
        tuple: A tuple containing the private key and the public key.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())  # Generate a private key
    public_key = private_key.public_key()  # Get the corresponding public key
    return private_key, public_key


def serialize_public_key(key):
    """
    Serializes a public key into PEM format.
    
    Args:
        key: The public key object to be serialized.
    
    Returns:
        str: The serialized public key in PEM format as a string.
    """
    pem_public_key = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_public_key.decode()


def serialize_private_key(private_key):
    """
    Serializes a private key into PEM format.

    Args:
        private_key (ec.PrivateKey): The private key to be serialized.

    Returns:
        str: The private key in PEM format.
    """
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No encryption for the key itself
    )

    return pem_private_key.decode('utf-8')


def derive_key(code, salt):
    """
    Derives a cryptographic key using PBKDF2HMAC with SHA256.
    
    Args:
        code (str): The input code to derive the key from.
        salt (bytes): A unique salt to be used in the derivation.
    
    Returns:
        bytes: The derived key of length 32 bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(code.encode())


def hash_message(message):
    """
    Computes the SHA-256 hash of the input message.
    
    Args:
        message (str): The message to be hashed.
    
    Returns:
        bytes: The resulting SHA-256 hash of the message.
    """
    digest = hashes.Hash(hashes.SHA256())  # Create an SHA-256 hashing context
    digest.update(message.encode())        # Update the context with the message
    return digest.finalize()               # Finalize and return the hash


def generate_aes_mac(message, aes_key):
    """
    Generates an AES-based MAC (Message Authentication Code) for the given message using CBC mode.
    
    Args:
        message (str): The message to be authenticated.
        aes_key (bytes): The AES key used for encryption.
    
    Returns:
        tuple: A tuple containing the generated MAC and the initialization vector (IV).
    """
    # Hash the message
    hashed_message = hash_message(message)
    
    # Generate a random IV for CBC mode
    iv = os.urandom(16)
    
    # Create AES cipher using CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the message to ensure it is a multiple of 16 bytes
    padded_message = hashed_message + b'\x00' * (16 - len(hashed_message) % 16)
    
    # Generate MAC by encrypting the padded message
    mac = encryptor.update(padded_message) + encryptor.finalize()

    return mac, iv


def verify_aes_mac(message, aes_key, received_mac, iv):
    """
    Verifies the MAC (Message Authentication Code) for the given message using AES in CBC mode.
    
    Args:
        message (str): The message whose MAC is to be verified.
        aes_key (bytes): The AES key used for encryption.
        received_mac (bytes): The MAC received to verify.
        iv (bytes): The initialization vector used for the AES cipher.
    
    Returns:
        bool: True if the computed MAC matches the received MAC, False otherwise.
    """
    # Hash the message
    hashed_message = hash_message(message)
    
    # Create AES cipher using CBC mode with the provided IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the message to ensure it's a multiple of the AES block size (16 bytes)
    padded_message = hashed_message + b'\x00' * (16 - len(hashed_message) % 16)
    
    # Compute the MAC by encrypting the padded message
    computed_mac = encryptor.update(padded_message) + encryptor.finalize()

    return computed_mac == received_mac


def recv_and_parse_json(sock):
    """
    Receive a message from a socket and parse it as JSON.

    Parameters:
        sock (socket.socket): The socket object to receive the message from.
    
    Returns:
        dict: The parsed JSON data.
    
    Raises:
        ConnectionError: If the message cannot be received fully.
        json.JSONDecodeError: If the received message is not valid JSON.
    """
    data = recv_message(sock)
    return json.loads(data)


def recv_message(sock):
    """
    Receive a message reliably over a socket, ensuring the full message is received.
    
    Parameters:
        sock (socket.socket): The socket object to receive the message from.
    
    Returns:
        str: The decoded message.
    
    Raises:
        ConnectionError: If the header or message is not received properly, or if the connection is closed prematurely.
    """
    # Read the 4-byte header to determine message length
    header = sock.recv(4)
    if len(header) < 4:
        raise ConnectionError("Failed to receive message header.")
    
    message_length = int.from_bytes(header, 'big')
    
    # Read the full message based on the length
    message_bytes = bytearray()
    while len(message_bytes) < message_length:
        chunk = sock.recv(message_length - len(message_bytes))
        if not chunk:
            raise ConnectionError("Connection closed before message was fully received.")
        message_bytes.extend(chunk)
    
    return message_bytes.decode('utf-8')


def send_message(sock, message):
    """
    Send a message reliably over a socket, ensuring the full message is sent.
    
    Parameters:
        sock (socket.socket): The socket object.
        message (str): The message to send.
    """
    # Convert message to bytes and prepend its length (4 bytes)
    message_bytes = message.encode()
    message_length = len(message_bytes)
    header = message_length.to_bytes(4, 'big')  # 4-byte header for message length
    
    # Send header and message
    sock.sendall(header + message_bytes)


def create_signature(message, private_key_pem):
    """
    Signs a message using ECDSA (Elliptic Curve Digital Signature Algorithm) and 
    the provided private key. The signature is created using SHA-256 hashing.

    Args:
        message (str): The message to be signed.
        private_key_pem (bytes): The private key in PEM format.

    Returns:
        bytes: The generated digital signature.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Sign the message with the private key using ECDSA and SHA-256
    signature = private_key.sign(
        message.encode(),  # Encode the message as bytes
        ec.ECDSA(hashes.SHA256())  # ECDSA with SHA-256 hash
    )
    return signature


def verify_signature(message, signature, public_key_pem):
    """
    Verifies the digital signature of a message using the ECDSA and the provided public key.

    Args:
        message (str): The message whose signature needs to be verified.
        signature (bytes): The digital signature to verify.
        public_key_pem (bytes): The public key in PEM format.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)

    try:
        # Verify the signature with the public key using ECDSA and SHA-256
        public_key.verify(
            signature,
            message.encode(),  # Encode the message as bytes
            ec.ECDSA(hashes.SHA256())  # ECDSA with SHA-256 hash
        )
        return True  # If no exception, signature is valid

    except InvalidSignature:
        return False  # Signature is invalid
    except (ValueError, TypeError) as e:
        # Handle cases where the input is not as expected
        print(f"Error: {e}")
        return False  # Signature verification failed due to incorrect input


def aes_encrypt(data):
    """
    Encrypts data using AES-256 in CBC mode and returns the key, IV, and ciphertext.

    Args:
        data (bytes): The data to encrypt.

    Returns:
        dict: Dictionary with 'key', 'iv', and 'ciphertext' as raw binary data.
    """
    # Generate a random key and IV
    key = os.urandom(32)  # AES-256 key (32 bytes)
    iv = os.urandom(16)   # IV for CBC mode (16 bytes)
    
    # Set up the AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad the data to make it a multiple of the block size (16 bytes)
    pad = padding.PKCS7(128).padder()
    padded_message = pad.update(data) + pad.finalize()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return the key, IV, and ciphertext as raw bytes
    return {
        "key": key,
        "iv": iv,
        "ciphertext": ciphertext
    }


def aes_decrypt(key, iv, ciphertext):
    """
    Decrypts ciphertext using AES-256 in CBC mode.

    Args:
        key (bytes): The AES encryption key (32 bytes for AES-256).
        iv (bytes): The initialization vector (16 bytes for CBC mode).
        ciphertext (bytes): The encrypted data.

    Returns:
        bytes: The original plaintext data.
    """
    # Set up the AES cipher in CBC mode for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove the padding
    unpad = padding.PKCS7(128).unpadder()
    plaintext = unpad.update(padded_message) + unpad.finalize()

    return plaintext


def generate_shared_secret(sender_private_key_pem, recipient_public_key_pem):
    """
    Generates a shared secret using Elliptic Curve Diffie-Hellman (ECDH).

    Args:
        sender_private_key_pem (bytes): Sender's private key in PEM format.
        recipient_public_key_pem (bytes): Recipient's public key in PEM format.

    Returns:
        bytes: The shared secret.
    """
    # Load the private key from PEM data
    private_key = serialization.load_pem_private_key(sender_private_key_pem, password=None)

    # Load the public key from PEM data
    public_key = serialization.load_pem_public_key(recipient_public_key_pem)

    # Generate the shared secret using ECDH
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    return shared_secret


def wrap_aes_key_with_derived_key(aes_key, derived_key):
    """
    Encrypts the AES key using a derived key with AES in ECB mode.

    Pads the AES key to the block size (16 bytes) using PKCS7 and encrypts it 
    with the provided derived key.

    Args:
        aes_key (bytes): AES key to be wrapped.
        derived_key (bytes): Key used for encryption, must be 16, 24, or 32 bytes.

    Returns:
        bytes: The wrapped AES key.
    """
    # Ensure aes_key is padded to the block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_aes_key = padder.update(aes_key) + padder.finalize()
    
    # Initialize the cipher with derived_key
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded AES key
    wrapped_key = encryptor.update(padded_aes_key) + encryptor.finalize()
    return wrapped_key


def unwrap_aes_key_with_derived_key(wrapped_key, derived_key):
    """
    Decrypts a wrapped AES key using a derived key with AES in ECB mode.

    Removes the PKCS7 padding to retrieve the original AES key.

    Args:
        wrapped_key (bytes): The wrapped AES key to be unwrapped.
        derived_key (bytes): Key used for decryption, must be 16, 24, or 32 bytes.

    Returns:
        bytes: The original AES key.
    """
    # Initialize the cipher with the derived key
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    decryptor = cipher.decryptor()
    
    # Decrypt the wrapped key
    padded_aes_key = decryptor.update(wrapped_key) + decryptor.finalize()
    
    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    aes_key = unpadder.update(padded_aes_key) + unpadder.finalize()
    
    return aes_key
