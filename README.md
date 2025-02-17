# E2EE Messaging App

## Overview
This messaging app implements end-to-end encryption (E2EE) for secure communication between clients. The system ensures that only the sender and recipient can read the message content, and it protects against eavesdropping or tampering. The app uses Elliptic Curve Cryptography (ECC) for key exchange, AES for message encryption, and ECDSA for digital signatures. Messages are sent over TCP connections, and all sensitive data is encrypted and authenticated to ensure privacy and integrity.

## Features
- **End-to-End Encryption (E2EE)**: All messages are encrypted on the sender's device and only decrypted on the recipient's device.
- **Public Key Infrastructure (PKI)**: Each client generates a pair of public and private keys using ECC for secure communication. Private keys remain secure on the client and are never transmitted.
- **Authentication**: User registration includes OTP (One-Time Password) verification, a secure key derivation process, and message integrity verification via MAC (Message Authentication Code).
- **Message Integrity**: Messages are signed with the sender's private key to verify their identity and ensure integrity, protecting against man-in-the-middle attacks.
- **Offline Messaging**: If the recipient is offline, messages are securely queued and delivered once they come online.
- **Multi-threading Support**: The server uses multi-threading to efficiently handle multiple client connections concurrently, enabling high scalability and responsiveness.
- **Secure Communication**: Messages are signed and encrypted, ensuring authenticity, privacy, and integrity.
- **TCP/IP Communication**: The application uses IPv4 and TCP sockets to establish secure and reliable connections between clients and the server, ensuring robust and continuous communication.

## Python Libraries
- `cryptography`: Provides encryption algorithms and key derivation functions (AES, HMAC, etc.).
- `socket`: Used for handling TCP/IP socket communication.
- `threading`: Used for creating and managing threads to handle multiple client connections concurrently.

## System Architecture

### Server Side
1. **Client Management**:
   - The server manages a dictionary of active clients (`clients`) indexed by their phone numbers.
   - Each client object contains information about the client's IP address, port, socket, public key, status (online/offline), and a message queue for offline messages.
2. **Socket Initialization**:
   - The server listens for incoming connections on IP `127.0.0.1` and port `8080`.
   - Each new connection spawns a new thread to handle communication with the client.
3. **Registration Process**:
   - Clients must register with their phone number and public key.
   - The server verifies the client's phone number, checks the client limit (`MAX_CLIENTS`), and sends a one-time password (OTP) for verification.
   - The client computes a derived key using the OTP and salt to generate a MAC (Message Authentication Code) and sends it to the server for validation.
4. **Message Handling**:
   - The server stores messages for offline clients and forwards messages to online clients immediately.
   - The server enforces a queue limit (`MAX_QUEUE_SIZE`) to prevent overload.

### Client Side
1. **Socket Communication**:
   - Clients create a socket to connect to the server using IPv4 and TCP.
   - Clients can send messages, request public keys of recipients, and disconnect securely.
2. **Key Generation**:
   - Clients generate an ECC key pair (public and private keys) during registration.
   - The public key is sent to the server for secure communication.
3. **Message Sending**:
   - Clients encrypt messages using AES with a random initialization vector (IV).
   - The message is wrapped with a shared secret derived from the client's private key and recipient's public key using ECDH.
   - A digital signature is applied to ensure the message's integrity and authenticity.
4. **Message Receiving**:
   - Clients receive encrypted messages from the server.
   - They verify the server’s signature and decrypt the AES key with the derived secret before decrypting the actual message.

## Key Technologies
- **Elliptic Curve Cryptography (ECC)**: Used for efficient and secure public-key cryptography.
- **ECDSA (Elliptic Curve Digital Signature Algorithm)**: Used for signing and verifying messages.
- **AES (Advanced Encryption Standard) in CBC Mode**: Used for encrypting and decrypting messages.
- **ECDH (Elliptic Curve Diffie-Hellman)**: Used to establish a shared secret between the sender and recipient.
- **KDF (Key Derivation Function)**: Ensures secure key generation for AES encryption and decryption.

## How It Works

### Client Registration
When a new user wants to register, they go through the following steps:
1. **Key Generation**: The client generates an ECC key pair (public and private keys). The private key is kept secure on the client device, while the public key is shared with the server.
2. **Phone Number Verification**: The user provides their phone number. The server checks that the phone number is not already registered and that the total number of active clients does not exceed the limit (`MAX_CLIENTS`).
3. **OTP Generation**: The server generates a one-time password (OTP) and a random salt. This OTP, along with the salt, is sent to the client to verify the phone number.
4. **OTP Verification**: The client enters the received OTP. The server verifies the OTP and ensures it’s valid based on the timestamp to avoid expiration.
5. **Key Derivation**: The client uses the OTP and the salt to generate a secret key via a Key Derivation Function (KDF). This key is used to generate a Message Authentication Code (MAC), which ensures the integrity of the registration data.
6. **MAC Verification**: The client sends the MAC, public key, phone number, and an initialization vector (IV) to the server. The server verifies the MAC and, if valid, stores the client’s public key and updates their status to “online”.

Once the client is registered successfully, they are ready to send and receive encrypted messages.

### Message Exchange
1. **Sending a Message**:
   - The client first requests the recipient's public key from the server. This request contains the sender’s phone number, the recipient’s phone number, and a signature to ensure the message integrity.
   - The server verifies the signature, checks if the recipient is registered, and if valid, sends the recipient's public key to the sender.
   - The sender then encrypts the message content (plaintext) using AES encryption in CBC mode. The AES key is generated from the shared secret between the sender and the recipient using ECDH (Elliptic Curve Diffie-Hellman) key exchange. This ensures that only the sender and recipient can decrypt the message.
   - The AES key is wrapped using the recipient's public key, ensuring that only the recipient can decrypt it with their private key.
   - The sender sends the encrypted message, wrapped AES key, IV, salt, and the sender’s phone number along with a digital signature for verification.
2. **Server Processing**:
   - The server verifies the sender’s signature and checks if the recipient is online.
   - If the recipient is online, the server sends the encrypted message to the recipient immediately.
   - If the recipient is offline, the server stores the message in a queue. Once the recipient connects, the server will send all queued messages in order.
   - If the queue exceeds the `MAX_QUEUE_SIZE`, the server will reject additional messages to prevent overload.
3. **Receiving a Message**:
   - When the recipient connects, they receive the encrypted message.
   - The recipient verifies the message's authenticity by checking the server’s signature on the message.
   - The recipient then decrypts the AES key using their private key and the shared secret derived through ECDH.
   - Finally, the recipient uses the decrypted AES key and IV to decrypt the ciphertext, recovering the original message.
4. **Message Integrity**:
   - Each message is signed by the sender using their private key. The server and the recipient can verify this signature to ensure that the message hasn’t been tampered with.

![Socket Connection Initialization](https://github.com/idorombaut/crypto/blob/main/draw.io/phase%20one.png)

![Registration](https://github.com/idorombaut/crypto/blob/main/draw.io/phase%20three.png)

![Sending and Receiving Messages](https://github.com/idorombaut/crypto/blob/main/draw.io/phase%20two.png)

## Limitations
- **Client Limit**: The server can handle up to 10 active clients at a time (configured by `MAX_CLIENTS`).
- **Message Queue Limit**: There is a maximum size for the message queue for each client (`MAX_QUEUE_SIZE`).

## Setup Instructions

### Step 1: Clone the Repository
```
git clone https://github.com/idorombaut/crypto.git
cd crypto
```

### Step 2: Set Up a Virtual Environment
1. **Create a Virtual Environment**
   ```
   python -m venv venv
   ```

2. **Activate the Virtual Environment**
   - **Windows**:
     ```
     .\venv\Scripts\activate
     ```
   - **macOS/Linux**:
     ```
     source venv/bin/activate
     ```

3. **Install Dependencies**
   ```
   pip install cryptography
   ```

### Step 3: Run the Server
```
python server.py
```

### Step 4: Run the Client
```
python client.py
```

![Chatting Client Side](https://github.com/idorombaut/crypto/blob/main/screenshots/chat%20alice.png)

![Chatting Server Side](https://github.com/idorombaut/crypto/blob/main/screenshots/chat%20server.png)
