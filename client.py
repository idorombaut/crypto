import socket
import json
import secrets
import threading
import queue
from utils import derive_key, generate_aes_mac, send_message, generate_and_serialize_keys, aes_encrypt, \
    verify_signature, generate_shared_secret, wrap_aes_key_with_derived_key, create_signature, \
    unwrap_aes_key_with_derived_key, aes_decrypt, recv_and_parse_json


# Load configuration from the config file
with open("config.json") as config_file:
    config = json.load(config_file)

host = config["host"]  # The server's host address
port = config["port"]  # The server's port number

# Global variable to store the serialized private key
serialized_private_key = None

# Global stop event to signal threads to stop
disconnect_flag = threading.Event()

# Global queue to hold responses received from the server
response_queue = queue.Queue()


def clean_phone_number(phone_number):
    """
    Removes non-digit characters from a phone number and returns only the digits.

    Args:
        phone_number (str): The raw phone number input by the user.

    Returns:
        str: The cleaned phone number containing only digits.
    """
    digits = ""
    for char in phone_number:
        if char.isdigit():
            digits += char
    return digits


def is_valid_phone_number(phone_number):
    """
    Validates whether the given phone number is in the correct format.

    Args:
        phone_number (str): The phone number to validate.

    Returns:
        tuple: A boolean indicating validity and an error message if invalid.
    """
    # Allowed characters in a phone number
    allowed_chars = "0123456789+-() "
    
    # Check if all characters are valid
    for char in phone_number:
        if char not in allowed_chars:
            return False, "Phone number contains invalid characters. Only digits, +, -, (), and spaces are allowed."

    # Remove non-digit characters
    digits = clean_phone_number(phone_number)

    # Check if the phone number contains between 7 and 15 digits
    if len(digits) < 7 or len(digits) > 15:
        return False, "Phone number must contain between 7 and 15 digits."

    # Check if the phone number starts with "+" and has no other "+"
    if phone_number.count("+") > 1 or (phone_number.count("+") == 1 and phone_number[0] != "+"):
        return False, "Phone number can only have one '+' symbol at the beginning."

    return True, ""


def send_phone_number(client_socket, phone_number):
    """
    Sends the phone number to the server for registration and handles the response.

    Args:
        client_socket (socket.socket): The connected socket to the server.
        phone_number (str): The client's phone number to be registered.

    Returns:
        bool: True if the phone number was successfully registered, False if there was an error.
    """
    phone_number_data = {
        "type": "register_phone_number",
        "phone_number": phone_number
    }
    send_message(client_socket, json.dumps(phone_number_data))
    
    response_data = recv_and_parse_json(client_socket)
    
    if response_data["status"] == "success":
        print(response_data["message"])
        return True
    elif response_data["status"] == "error":
        print(response_data["message"])
    
    return False


def handle_verification_code(client_socket):
    """
    Prompts the user to input a verification code, sends the input to the server for validation,
    and handles the server's response (success, invalid, or expired).

    Args:
        client_socket (socket.socket): The connected socket to the server.

    Returns:
        bool: True if the verification code is successfully validated, False if invalid or expired.
    """
    while True:
        user_input_code = input("Enter verification code: ")

        # Send the verification code to the server
        code_validation_data = {
            "type": "verify_code",
            "verification_code": user_input_code
        }
        send_message(client_socket, json.dumps(code_validation_data))

        # Receive the server's response
        response_data = recv_and_parse_json(client_socket)
        
        if response_data["status"] == "success":
            print(response_data["message"])
            return True
        elif response_data["status"] == "expired":
            print(response_data["message"])
            return False
        elif response_data["status"] == "invalid":
            print(response_data["message"])
        else:
            return False


def send_registration_data(client_socket, phone_number, public_key, derived_key):
    """
    Sends registration data (phone number, public key, MAC, IV) to the server and processes the response.

    Args:
        client_socket (socket.socket): The connected socket for communication.
        phone_number (str): The client's phone number.
        public_key (str): The client's serialized public key.
        derived_key (bytes): The key used to generate the MAC and IV.

    Returns:
        bool: 'True' if registration succeeds (server returns success), 'False' otherwise.
    """
    # Prepare the registration message
    message = f"{phone_number}{public_key}"

    # Generate MAC and IV using the derived key
    mac, iv = generate_aes_mac(message, derived_key)

    # Prepare the registration data dictionary
    registration_data = {
        "type": "registration",
        "phone_number": phone_number,
        "public_key": public_key,
        "mac": mac.hex(),
        "iv": iv.hex()
    }
    # Send registration data to server
    send_message(client_socket, json.dumps(registration_data))

    # Receive the server's response
    response_data = recv_and_parse_json(client_socket)
    
    if response_data["status"] == "success":
        print(response_data["message"])
        return True
    elif response_data["status"] == "error":
        print(response_data["message"])
    
    return False


def register_with_server(client_socket, public_key):
    """
    Registers a client with the server by:
    1. Prompting for and validating the phone number.
    2. Sending the phone number to the server.
    3. Receiving and verifying a verification code.
    4. Deriving a key from the verification code and salt.
    5. Sending the registration data to the server.

    Args:
        client_socket (socket.socket): The socket for server communication.
        public_key (str): The client's public key.

    Returns:
        str or None: The phone number on success, None on failure.
    """
    # Continuous prompt for a valid phone number
    while True:
        phone_number = input("Enter your phone number: ")

        is_valid, error_message = is_valid_phone_number(phone_number)
        if is_valid:
            print("Valid phone number!")
            phone_number = clean_phone_number(phone_number)
            break  # Exit the loop
        else:
            print(f"Invalid phone number. Reason: {error_message}")

    try:
        # Step 1: Send phone number
        if not send_phone_number(client_socket, phone_number):
            return None

        # Step 2: Receive verification code
        response_data = recv_and_parse_json(client_socket)
        verification_code = response_data["verification_code"]
        salt = bytes.fromhex(response_data["salt"])

        print(f"Received verification code: {verification_code}")

        # Step 3: Handle verification
        if not handle_verification_code(client_socket):
            return None
        
        # Derive the key using the verification code and salt
        derived_key = derive_key(verification_code, salt)

        # Step 4: Send registration data
        if not send_registration_data(client_socket, phone_number, public_key, derived_key):
            return None

        return phone_number

    except Exception as e:
        print(f"Error during registration: {e}")
        return None


def send_public_key_request(client_socket, phone_number, recipient_phone_number, server_public_key):
    """
    Requests the recipient's public key from the server by sending a public key request.

    Args:
        client_socket (socket.socket): The connected socket to the server.
        phone_number (str): The sender's phone number, used to identify the requester.
        recipient_phone_number (str): The recipient's phone number.
        server_public_key (str): The server's public key.

    Returns:
        str or None: The recipient's public key if successful, None otherwise.
    """
    # Prepare the message and create a signature
    message = f"{phone_number}{recipient_phone_number}"
    signature = create_signature(message, serialized_private_key.encode())

    # Prepare the request data
    request_data = {
        "type": "public_key_request",
        "phone_number": phone_number,
        "recipient_phone_number": recipient_phone_number,
        "signature": signature.hex()
    }
    # Send the request to the server
    send_message(client_socket, json.dumps(request_data))

    # Receive and process the response
    response_data = get_response("public_key_response")

    if response_data["status"] == "success":
        recipient_public_key = response_data["public_key"]
        signature = bytes.fromhex(response_data["signature"])
        
        # Verify the signature
        if verify_signature(recipient_public_key, signature, server_public_key.encode()):
            return recipient_public_key
        else:
            print("Error: Invalid signature for the public key.")
            return None
    elif response_data["status"] == "error":
        print(response_data["message"])
        return None
    

def encrypt_and_send(client_socket, phone_number, recipient_phone_number, recipient_public_key, message):
    """
    Encrypts a message securely using AES encryption, wraps the encryption key using a derived key based on
    a shared secret, and sends the encrypted message along with necessary metadata to the server.

    Args:
        client_socket (socket.socket): The socket connection to the server for communication.
        phone_number (str): The sender's phone number.
        recipient_phone_number (str): The recipient's phone number.
        recipient_public_key (str): The recipient's serialized public key.
        message (str): The plaintext message to encrypt and send.

    Returns:
        None
    """
    # Step 1: Encrypt the message with AES
    encrypted_data = aes_encrypt(message.encode())

    # Extract the AES encryption components
    aes_key = encrypted_data["key"]
    iv = encrypted_data["iv"]
    ciphertext = encrypted_data["ciphertext"]
    
    # Step 2: Generate the shared secret using client's private key and recipient's public key
    shared_secret = generate_shared_secret(serialized_private_key.encode(), recipient_public_key.encode())

    # Step 3: Generate a random salt for key derivation
    salt = secrets.token_bytes(16)
    
    # Step 4: Derive the key using the shared secret and the salt
    derived_key = derive_key(shared_secret.hex(), salt)

    # Step 5: Wrap the AES key with the derived key
    wrapped_aes_key = wrap_aes_key_with_derived_key(aes_key, derived_key)

    # Convert all components to hex format for transmission
    ciphertext_hex = ciphertext.hex()
    wrapped_key_hex = wrapped_aes_key.hex()
    iv_hex = iv.hex()
    salt_hex = salt.hex()
    
    # Step 6: Construct the message to send
    message_to_send = f"{ciphertext_hex}{wrapped_key_hex}{iv_hex}{salt_hex}{phone_number}{recipient_phone_number}"
    
    # Create a signature for the message to ensure integrity
    signature = create_signature(message_to_send, serialized_private_key.encode())

    # Prepare the final message data with all components
    secure_message_data = {
        "type": "outgoing_encrypted_message",
        "ciphertext": ciphertext_hex,
        "wrapped_key": wrapped_key_hex,
        "iv": iv_hex,
        "salt": salt_hex,
        "phone_number": phone_number,
        "recipient_phone_number": recipient_phone_number,
        "signature": signature.hex()
    }
    # Step 7: Send the encrypted message data to the server
    send_message(client_socket, json.dumps(secure_message_data))


def fetch_and_decrypt(server_public_key):
    """
    Fetches an incoming encrypted message from the server, verifies its signature, decrypts the message,
    and prints it out with the sender's phone number.

    Args:
        server_public_key (str): The public key of the server used for signature verification.

    Returns:
        None
    """
    # Fetch the response containing the encrypted message
    response_data = get_response("incoming_encrypted_message")

    if response_data is None:
        return

    # Extract message components from the response
    ciphertext_hex = response_data["ciphertext"]
    wrapped_key_hex = response_data["wrapped_key"]
    iv_hex = response_data["iv"]
    salt_hex = response_data["salt"]
    sender_phone_number = response_data["sender_phone_number"]
    sender_public_key = response_data["sender_public_key"]
    signature = bytes.fromhex(response_data["signature"])

    # Construct the message to verify the signature
    message_to_receive = f"{ciphertext_hex}{wrapped_key_hex}{iv_hex}{salt_hex}{sender_phone_number}{sender_public_key}"
    
    # Verify the signature of the incoming message
    if verify_signature(message_to_receive, signature, server_public_key.encode()):
        # Convert hex-encoded data back into bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        wrapped_key = bytes.fromhex(wrapped_key_hex)
        iv = bytes.fromhex(iv_hex)
        salt = bytes.fromhex(salt_hex)
        
        # Derive the shared secret using the client's private key and the sender's public key
        shared_secret = generate_shared_secret(serialized_private_key.encode(), sender_public_key.encode())
        
        # Derive the AES key from the shared secret and the salt
        derived_key = derive_key(shared_secret.hex(), salt)
        
        # Unwrap the AES key using the derived key
        aes_key = unwrap_aes_key_with_derived_key(wrapped_key, derived_key)
        
        # Decrypt the message using AES decryption
        message = aes_decrypt(aes_key, iv, ciphertext).decode()

        # Format and print the decrypted message along with the sender's phone number
        formatted_message = f"\033[1;31m{sender_phone_number}: {message}\033[0m"
        print(formatted_message)
    else:
        print("Error: Invalid signature for the message.")


def handle_sending_messages(client_socket, phone_number, server_public_key):
    """
    Handles sending messages from the client to other users. Allows the user to input a recipient's phone number,
    validates it, fetches the recipient's public key, encrypts the message, and sends it securely to the server.

    Args:
        client_socket (socket.socket): The socket connection to the server for communication.
        phone_number (str): The sender's phone number.
        server_public_key (str): The server's public key for secure requests.

    Returns:
        None
    """
    print("Please enter the recipient's phone number or type 'disconnect' to exit.")
    print("After that, enter your message.")

    while not disconnect_flag.is_set():
        user_input = input("")

        if user_input.lower() == "disconnect":
            # Notify the server about the disconnection
            disconnect_data = {
                "type": "disconnect",
                "phone_number": phone_number
            }
            send_message(client_socket, json.dumps(disconnect_data))
            
            disconnect_flag.set()
            print("Disconnecting...")

        elif is_valid_phone_number(user_input)[0]:
            recipient_phone_number = clean_phone_number(user_input)
        
            # Request recipient's public key
            recipient_public_key = send_public_key_request(client_socket, phone_number, recipient_phone_number,
                                                           server_public_key)

            if recipient_public_key:
                # Get the message from the user
                message = input("")

                # Encrypt and send the message
                encrypt_and_send(client_socket, phone_number, recipient_phone_number, recipient_public_key, message)

        else:
            print("Invalid input. Please try again.")


def handle_receiving_messages(server_public_key):
    """
    Handles the process of receiving incoming messages from the server. This function runs in a separate thread
    to continuously fetch and decrypt incoming messages.

    Args:
        server_public_key (str): The server's public key used for verifying message signatures.
    """
    while not disconnect_flag.is_set():
        fetch_and_decrypt(server_public_key)
 

def handle_responses(client_socket):
    """
    Listens for incoming server responses and adds them to the response queue for further processing.

    Args:
        client_socket (socket.socket): The socket used for communication with the server.
    """
    try:
        while True:
            response_data = recv_and_parse_json(client_socket)

            # Add the response to the queue for processing by other threads
            response_queue.put(response_data)
    except ConnectionError:
        response_queue.put({"type": "disconnect"})


def get_response(expected_type):
    """
    Retrieves and returns a response from the queue that matches the expected type.

    Args:
        expected_type (str): The type of response to retrieve from the queue.

    Returns:
        dict or None: Returns the response data if the type matches 'expected_type',
                      or None if a "disconnect" message is received.
    """
    while True:
        response_data = response_queue.get()  # Blocking call
        if response_data["type"] == "disconnect":
            return None
        elif response_data["type"] == expected_type:
            return response_data  # Return the matched message
        else:
            # If message doesn't match, re-add to queue for other threads
            response_queue.put(response_data)
        

def run_client():
    """
    Runs the client application, which involves generating keys, registering with the server,
    and starting threads for sending and receiving messages.

    This function initializes the socket connection, manages the threads, and handles the client interaction.
    """
    global serialized_private_key

    # Generate keys
    serialized_public_key, serialized_private_key = generate_and_serialize_keys()

    # Load the server's public key
    with open("server_public_key.pem", "r") as f:
        server_public_key = f.read()

    # Create a socket connection to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    try:
        # Register the client with the server
        phone_number = register_with_server(client_socket, serialized_public_key)

        if phone_number is None:
            return
        
        # Start the centralized receiver thread
        response_thread = threading.Thread(target=handle_responses, args=(client_socket,), daemon=True)
        response_thread.start()
        
        # Create threads for sending and receiving messages
        send_thread = threading.Thread(target=handle_sending_messages, args=(client_socket, phone_number,
                                                                             server_public_key))
        receive_thread = threading.Thread(target=handle_receiving_messages, args=(server_public_key,))

        send_thread.start()
        receive_thread.start()

        # Wait for threads to finish
        send_thread.join()
        receive_thread.join()

    except KeyboardInterrupt:
        print("Client interrupted by user. Closing client...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Connection to server closed")


if __name__ == "__main__":
    run_client()
