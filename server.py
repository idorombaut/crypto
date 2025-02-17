import os
import time
import socket
import secrets
import json
import threading
from utils import derive_key, verify_aes_mac, send_message, generate_and_serialize_keys, \
    create_signature, verify_signature, recv_and_parse_json
from client_class import Client


MAX_CLIENTS = 10  # Maximum number of clients allowed
CODE_VALIDITY_PERIOD = 30  # The validity period for the verification code in seconds

# Load configuration from the config file
with open("config.json") as config_file:
    config = json.load(config_file)

host = config["host"]
port = config["port"]

# Global variable for the server's serialized private key
serialized_private_key = None

clients = {}  # Dictionary to store registered clients, using phone number as the key

clients_lock = threading.Lock()  # Lock for thread safety


def send_by_secure_channel(client_socket):
    """
    Generates a 6-digit verification code, sends it along with a random salt to the client through a secure socket
    channel, and returns the generated verification code.

    Args:
        client_socket (socket.socket): The socket connection with the client.

    Returns:
        tuple:
            - verification_code (str): A 6-digit string verification code.
            - salt (bytes): A 16-byte random salt.
    """
    # Generate a 6-digit verification code
    verification_code = str(secrets.randbelow(10**6)).zfill(6)
    
    # Generate a random 16-byte salt
    salt = secrets.token_bytes(16)
    
    # Create a response with the verification code
    response = {
        "verification_code": verification_code,
        "salt": salt.hex()
    }
    # Send the response to the client
    send_message(client_socket, json.dumps(response))

    return verification_code, salt


def receive_registration_request(client_socket, addr):
    """
    Handles the initial step of client registration by receiving and validating 
    the phone number provided by the client.

    Args:
        client_socket (socket.socket): The socket connection with the client.
        addr (tuple): The address of the client (IP, port).

    Returns:
        str or None: Returns the phone number if registration is successful, 
                     or None if registration fails (e.g., phone number already exists).
    """
    # Receive the phone number from the client
    phone_number_data = recv_and_parse_json(client_socket)

    if phone_number_data["type"] == "register_phone_number":
        phone_number = phone_number_data["phone_number"]
        
        print(f"Received phone number from {addr}: {phone_number}")

        # Add the client to the clients dictionary (if not already added)
        with clients_lock:
            # Check if maximum limit is reached
            if len(clients) >= MAX_CLIENTS:
                response = {
                    "status": "error",
                    "message": "Maximum client limit reached."
                }
                send_message(client_socket, json.dumps(response))
                
                print(f"Registration failed for {phone_number}. Maximum client limit reached.")
                return None
            
            # Check if the phone number is already registered
            if phone_number in clients:
                response = {
                    "status": "error",
                    "message": "This phone number is already registered."
                }
                send_message(client_socket, json.dumps(response))
                
                print(f"Phone number {phone_number} is already registered. Registration aborted.")
                return None
            else:
                client = Client(addr, client_socket, phone_number, None)  # Public key will be set later
                clients[phone_number] = client
                
                response = {
                    "status": "success",
                    "message": "Phone number accepted. Finalizing registration."
                }
                send_message(client_socket, json.dumps(response))
                
                print(f"Client {addr} with phone number {phone_number} added to the clients dictionary.")
                return phone_number

    return None


def send_verification_code(phone_number):
    """
    Sends a verification code to the client securely and records the time of its generation.

    Args:
        phone_number (str): The phone number associated with the client.

    Returns:
        tuple: A tuple containing the verification code (str), the salt (bytes),
               and the timestamp (float) of when the code was generated.
    """
    with clients_lock:
        client = clients.get(phone_number)
    
    # Send the verification code and record its generation time
    verification_code, salt = send_by_secure_channel(client.get_client_socket())
    verification_code_timestamp = time.time()  # Record the time of generation
    
    print(f"Sent verification code to {client.get_addr()}.")
    
    return verification_code, salt, verification_code_timestamp


def verify_code(phone_number, verification_code, verification_code_timestamp, code_validity_period):
    """
    Verifies the code sent by the client within the allowed validity period.

    Args:
        phone_number (str): The phone number associated with the client requesting verification.
        verification_code (str): The code sent to the client for verification.
        verification_code_timestamp (float): The timestamp when the verification code was generated.
        code_validity_period (int): The time period (in seconds) for which the verification code is valid.

    Returns:
        bool: True if the client successfully verifies the code, 
              False if the code is invalid or expired.
    """
    with clients_lock:
        client = clients.get(phone_number)
    
    while True:
        # Receive the verification code from the client
        code_validation_data = recv_and_parse_json(client.get_client_socket())

        if code_validation_data["type"] == "verify_code":
            client_code = code_validation_data["verification_code"]
            
            # Check if the verification code has expired
            if time.time() - verification_code_timestamp > code_validity_period:
                response = {
                    "status": "expired",
                    "message": "Verification code expired. Please register again."
                }
                send_message(client.get_client_socket(), json.dumps(response))
                
                print(f"Verification code expired for {client.get_addr()}.")
                remove_client(phone_number, client.get_client_socket(), client.get_addr())
                return False
            
            # Check if the verification code matches
            if client_code == verification_code:
                response = {
                    "status": "success",
                    "message": "Verification code correct!"
                }
                send_message(client.get_client_socket(), json.dumps(response))
                
                print(f"Verification code validated for {client.get_addr()}.")
                return True
            else:
                response = {
                    "status": "invalid",
                    "message": "Invalid verification code. Please try again."
                }
                send_message(client.get_client_socket(), json.dumps(response))
                
                print(f"Verification code mismatch for {client.get_addr()}. Client prompted to try again.")

        else:
            return False
    

def process_registration_data(phone_number, verification_code, salt):
    """
    Processes the registration data received from the client, including 
    validating the MAC and updating the client's public key upon successful verification.

    Args:
        phone_number (str): The phone number of the client attempting to register.
        verification_code (str): The verification code sent to the client during registration.
        salt (bytes): The salt used to derive the key for MAC verification.

    Returns:
        bool: True if the registration data is successfully verified and processed,
              False if MAC verification fails or registration data is invalid.
    """
    with clients_lock:
        client = clients.get(phone_number)
    
    # Receive registration data from the client (phone number, public key, MAC)
    registration_data = recv_and_parse_json(client.get_client_socket())

    if registration_data["type"] == "registration":
        phone_number = registration_data["phone_number"]
        public_key = registration_data["public_key"]
        received_mac = bytes.fromhex(registration_data["mac"])
        iv = bytes.fromhex(registration_data["iv"])
        
        print(f"Received registration data from {client.get_addr()}.")

        # Derive the key using the verification code and salt
        derived_key = derive_key(verification_code, salt)
        
        # Construct the message to verify MAC
        message = f"{phone_number}{public_key}"

        # Verify the MAC using the derived key
        if verify_aes_mac(message, derived_key, received_mac, iv):
            # Update the client object with the public key
            with clients_lock:
                client.set_public_key(public_key)
            
            print(f"Client {client.get_addr()} public key set.")
            
            response = {
                "status": "success",
                "message": "Registration successful!"
            }
            send_message(client.get_client_socket(), json.dumps(response))
            
            print(f"MAC verified for {client.get_addr()}. Registration successful.")
            return True
        else:
            response = {
                "status": "error",
                "message": "MAC verification failed."
            }
            send_message(client.get_client_socket(), json.dumps(response))
            
            print(f"MAC verification failed for {client.get_addr()}.")
            remove_client(phone_number, client.get_client_socket(), client.get_addr())
    
    return False


def handle_client_registration(client_socket, addr):
    """
    Handles the client registration process, including:
    - Receiving registration request (phone number).
    - Sending and verifying a verification code.
    - Processing registration data.
    - Setting the client's status to 'online' upon success.

    Parameters:
        client_socket (socket.socket): Socket for communication with the client.
        addr (tuple): Client's address (IP, port).

    Returns:
        str or None: Client's phone number if registration is successful, None otherwise.
    """
    print(f"Handling registration for {addr}")

    phone_number = None  # Initialize to a default value
    
    try:
        # Step 1: Receive registration request
        phone_number = receive_registration_request(client_socket, addr)

        if phone_number is None:
            return None

        # Step 2: Send verification code
        verification_code, salt, verification_code_timestamp = send_verification_code(phone_number)
        code_validity_period = CODE_VALIDITY_PERIOD

        # Step 3: Verify the code
        if not verify_code(phone_number, verification_code, verification_code_timestamp, code_validity_period):
            return None

        # Step 4: Process registration data
        if not process_registration_data(phone_number, verification_code, salt):
            return None
        
        # Step 5: Set the client's status to 'online' after successful registration
        with clients_lock:
            client = clients.get(phone_number)
            client.set_status("online")
        
        return phone_number

    except Exception as e:
        print(f"Error with client {addr}: {e}")
        remove_client(phone_number, client_socket, addr)


def remove_client(phone_number, client_socket, addr):
    """
    Removes the client with the given phone number and closes their connection.

    Args:
        phone_number (str or None): The phone number of the client to be removed.
        client_socket (socket.socket): The socket object representing the client connection.
        addr (tuple): A tuple containing the client's IP address and port number (addr[0], addr[1]).

    Returns:
        None
    """
    # Check if the socket is already closed
    if client_socket.fileno() != -1:
        # Close the client's socket connection
        client_socket.close()
        print(f"Connection to client ({addr[0]}:{addr[1]}) closed")

    with clients_lock:
        # Check if the phone_number exists in the clients dictionary
        if phone_number in clients:
            # Remove the client from the clients dictionary using the phone number
            del clients[phone_number]
            print(f"Client with phone number {phone_number} has been removed.")


def handle_public_key_request(request_data):
    """
    Handles incoming requests for a recipient's public key, verifies the request signature, 
    and responds with the public key and signature if valid.

    Args:
        request_data (dict): The data from the public key request, containing:
        - "phone_number" (str): The sender's phone number.
        - "recipient_phone_number" (str): The recipient's phone number.
        - "signature" (str): The sender's signature of the message, represented as a hexadecimal string.
    
    Returns:
        bool: Returns True if the public key request was handled successfully, False otherwise.
    """
    sender_phone_number = request_data["phone_number"]
    recipient_phone_number = request_data["recipient_phone_number"]
    signature = bytes.fromhex(request_data["signature"])
    
    # Verify the signature of the request message
    message = f"{sender_phone_number}{recipient_phone_number}"

    # Retrieve the sender's Client object from the dictionary
    with clients_lock:
        sender_client = clients.get(sender_phone_number)
    
    if verify_signature(message, signature, sender_client.get_public_key().encode()):
        # Retrieve the recipient's Client object from the dictionary
        with clients_lock:
            recipient_client = clients.get(recipient_phone_number)

        if recipient_client:
            # Sign the public key with the server's private key
            signature = create_signature(recipient_client.get_public_key(), serialized_private_key.encode())

            # Prepare the response data
            response_to_sender = {
                "type": "public_key_response",
                "status": "success",
                "public_key": recipient_client.get_public_key(),
                "signature": signature.hex()
            }
            send_message(sender_client.get_client_socket(), json.dumps(response_to_sender))
            
            return True
        else:
            # If the public key is not found, return an error response
            response_to_sender = {
                "type": "public_key_response",
                "status": "error",
                "message": "Phone number not registered."
            }
            send_message(sender_client.get_client_socket(), json.dumps(response_to_sender))
            
            return False
    else:
        print("Error: Invalid signature for the public key.")
        return False


def monitor_client_status():
    """
    Periodically checks the status of all clients and sends queued messages to those who come online.

    This function runs in a separate thread to continuously monitor client status and ensure message delivery 
    to clients who are now online. It checks the client status every 5 seconds.
    """
    while True:
        with clients_lock:
            for client in clients.values():
                previous_status = client.get_status()
                client.check_status()

                if client.get_status() == "online" and previous_status == "offline":
                    # If the client is now online, send any queued messages
                    client.send_queued_messages()

        time.sleep(5)  # Check status every 5 seconds


def handle_encrypted_message(secure_message_data):
    """
    Handles incoming encrypted messages, verifies the signature, and forwards the message to the recipient 
    if they are online or queues it if they are offline.

    Args:
        secure_message_data (dict): Data containing message details such as ciphertext, wrapped key, sender
        and recipient info, etc.

    Returns:
        bool: Returns True if the message was handled successfully, False if there was an error
        (e.g., invalid signature).
    """
    ciphertext = secure_message_data["ciphertext"]
    wrapped_key = secure_message_data["wrapped_key"]
    iv = secure_message_data["iv"]
    salt = secure_message_data["salt"]
    sender_phone_number = secure_message_data["phone_number"]
    recipient_phone_number = secure_message_data["recipient_phone_number"]
    signature = bytes.fromhex(secure_message_data["signature"])

    message = f"{ciphertext}{wrapped_key}{iv}{salt}{sender_phone_number}{recipient_phone_number}"

    # Retrieve the sender's Client object from the dictionary
    with clients_lock:
        sender_client = clients.get(sender_phone_number)
    
    # Verify the signature of the incoming message
    if verify_signature(message, signature, sender_client.get_public_key().encode()):
        with clients_lock:
            recipient_client = clients.get(recipient_phone_number)

        if recipient_client:
            recipient_client.check_status()

            # Create a new message to send to the recipient
            new_message = f"{ciphertext}{wrapped_key}{iv}{salt}{sender_phone_number}{sender_client.get_public_key()}"
            
            new_signature = create_signature(new_message, serialized_private_key.encode())
            
            response_to_recipient = {
                "type": "incoming_encrypted_message",
                "ciphertext": ciphertext,
                "wrapped_key": wrapped_key,
                "iv": iv,
                "salt": salt,
                "sender_phone_number": sender_phone_number,
                "sender_public_key": sender_client.get_public_key(),
                "signature": new_signature.hex()
            }

            if recipient_client.get_status() == "online":
                # Deliver queued messages before the new one
                recipient_client.send_queued_messages()
                
                send_message(recipient_client.get_client_socket(), json.dumps(response_to_recipient))
                
                print(f"Message delivered to {recipient_phone_number}.")
            else:
                # If the recipient is offline, store the message for later delivery
                print(f"Recipient {recipient_phone_number} is offline. Storing the message.")
                
                recipient_client.add_message_to_queue(response_to_recipient)

            return True
        else:
            print(f"Error: Recipient {recipient_phone_number} not found.")
            return False
    else:
        print("Error: Invalid signature for the message.")
        return False


def handle_client(client_socket, addr):
    """
    Handles the communication with a single client, including registration, processing incoming messages, 
    and handling disconnect requests.

    Args:
        client_socket (socket.socket): The socket connection with the client.
        addr (tuple): The address of the client.
    """
    phone_number = None  # Initialize to a default value

    try:
        # First, handle the client's registration
        phone_number = handle_client_registration(client_socket, addr)

        if phone_number is None:
            return

        # Continuously receive and process messages
        while True:
            message_data = recv_and_parse_json(client_socket)
            
            # Process different types of messages
            if message_data["type"] == "disconnect":
                phone_number = message_data["phone_number"]
                break
            elif message_data["type"] == "public_key_request":
                handle_public_key_request(message_data) 
            elif message_data["type"] == "outgoing_encrypted_message":
                handle_encrypted_message(message_data)
            else:
                break

    except Exception as e:
        print(f"Error when handling client: {e}")
    finally:
        # Remove client from active list
        remove_client(phone_number, client_socket, addr)


def start_server():
    """
    Starts the server, listens for incoming client connections, and assigns client handling to separate threads.

    The server generates keys, listens for incoming connections, and assigns each client to a separate thread 
    for handling their messages. It also starts a thread to monitor client statuses.
    """
    global serialized_private_key

    # Generate keys for the server
    serialized_public_key, serialized_private_key = generate_and_serialize_keys()

    # Save the public key to a file for use by clients
    with open("server_public_key.pem", "w") as f:
        f.write(serialized_public_key)
    
    # Start the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)  # Max number of queued connections

    print(f"Server is running on {host}:{port}... Waiting for client connections.")
    print("To stop the server, press Ctrl+C.")
    
    # Start a thread to monitor client statuses
    monitor_thread = threading.Thread(target=monitor_client_status, daemon=True)
    monitor_thread.start()

    try:
        while True:
            # Accept incoming client connections
            client_socket, addr = server_socket.accept()
            print(f"Connection established with {addr}")
            
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.start()

    except KeyboardInterrupt:
        print("Server interrupted by user. Closing server...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the server socket when done
        server_socket.close()
        print("Server has been shut down.")

        # Remove the public key file after the server shuts down
        if os.path.exists("server_public_key.pem"):
            os.remove("server_public_key.pem")


# Start the server when the script is run
if __name__ == "__main__":
    start_server()
