import random
import json
from utils import send_message


MAX_QUEUE_SIZE = 2  # Maximum number of messages allowed in the queue


class Client:
    """
    Represents a client in the system with relevant details such as address, 
    socket connection, phone number, public key, status (online/offline), and a message queue.
    """
    def __init__(self, addr, client_socket, phone_number, public_key, status="offline"):
        """
        Initializes the client object with the provided attributes.
        
        Args:
            addr (tuple): The address of the client (IP, port).
            client_socket (socket.socket): The socket associated with the client connection on the server.
            phone_number (str): The phone number of the client.
            public_key (str or None): Client's public key (serialized format), or None if unavailable.
            status (str): The status of the client, either 'online' or 'offline'. Default is 'offline'.
        """
        self.__addr = addr                    # Client's address (IP, port)
        self.__client_socket = client_socket  # The socket for client-server communication
        self.__phone_number = phone_number    # Store the phone number
        self.__public_key = public_key        # The public key of the client, which can be None
        self.__status = status                # The status of the client (online/offline)
        self.__message_queue = []             # Queue to store messages when the client is offline

    def get_addr(self):
        """
        Retrieves the client's address (IP, port).
        
        Returns:
            tuple: The address of the client in the format (IP, port).
        """
        return self.__addr
    
    def set_addr(self, addr):
        """
        Sets the client's address (IP, port).
        
        Args:
            addr (tuple): The new address of the client.
        """
        self.__addr = addr
    
    def get_client_socket(self):
        """
        Retrieves the client's socket object.
        
        Returns:
            socket.socket: The socket associated with the client.
        """
        return self.__client_socket
    
    def set_client_socket(self, client_socket):
        """
        Sets the client's socket object.
        
        Args:
            client_socket (socket.socket): The new socket associated with the client.
        """
        self.__client_socket = client_socket
    
    def get_phone_number(self):
        """
        Retrieves the client's phone number.
        
        Returns:
            str: The phone number associated with the client.
        """
        return self.__phone_number
    
    def set_phone_number(self, phone_number):
        """
        Sets the client's phone number.
        
        Args:
            phone_number (str): The new phone number of the client.
        """
        self.__phone_number = phone_number
    
    def get_public_key(self):
        """
        Retrieves the client's public key.
        
        Returns:
            str: The public key associated with the client.
        """
        return self.__public_key
    
    def set_public_key(self, public_key):
        """
        Sets the client's public key.
        
        Args:
            public_key (str): The new public key of the client.
        """
        self.__public_key = public_key
    
    def get_status(self):
        """
        Retrieves the client's current status.
        
        Returns:
            str: The status of the client, either 'online' or 'offline'.
        """
        return self.__status
    
    def set_status(self, status):
        """
        Updates the status of the client manually.
        
        Args:
            status (str): The new status of the client, either 'online' or 'offline'.
        """
        if status not in ["online", "offline"]:
            raise ValueError("Status must be either 'online' or 'offline'.")
        self.__status = status
    
    def get_message_queue(self):
        """
        Retrieves the client's message queue.
        
        Returns:
            list: The list of messages in the client's queue.
        """
        return self.__message_queue
    
    def set_message_queue(self, message_queue):
        """
        Sets the client's message queue.
        
        Args:
            message_queue (list): The new message queue.
        """
        self.__message_queue = message_queue
    
    def check_status(self):
        """
        Updates the client's status based on the is_client_online function.
        """
        self.__status = is_client_online()

    def add_message_to_queue(self, message):
        """
        Adds a message to the queue. Ensures the queue has at most 2 messages.
        """
        if len(self.__message_queue) >= MAX_QUEUE_SIZE:
            self.__message_queue.pop(0)  # Remove the oldest message
        self.__message_queue.append(message)
    
    def send_queued_messages(self):
        """
        Sends all queued messages to the client in FIFO order.
        """
        while self.__message_queue:
            queued_message = self.__message_queue.pop(0)
            send_message(self.__client_socket, json.dumps(queued_message))
            print(f"Message delivered to {self.__phone_number}.")
    
    def __str__(self):
        """
        Provides a string representation of the Client object.
        
        Returns:
            str: A string describing the client, including address.
        """
        return f"Client({self.__addr})"


def is_client_online():
    """
    Randomly determines the online status of a client.
    
    Returns:
        str: A string representing the client's status, either 'online' or 'offline'.
        
    This function simulates the checking of the client's online status by randomly choosing
    between 'online' and 'offline'.
    """
    # Randomly choose between 'online' and 'offline'
    status = random.choice(["online", "offline"])
    return status
