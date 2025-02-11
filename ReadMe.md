# Secure Parallel Communicator v9.1

## Overview

This Python project is a secure communication tool that implements multi-channel data transfer over several ports and protocols. It features robust encryption methods, a multi-secured handshake mechanism, dynamic key rotation, and message splitting across multiple connections. **Please note:** This project is primarily a thought experiment. Although it employs several advanced security techniques, it has not been subjected to extensive security audits and is not intended for production use. Contributions and ideas to further improve its security are very welcome.

## Features

- **Multi-Channel Communication**  
  The application sets up multiple server sockets on different ports and supports client connections across these ports.
  
- **Encryption**  
  Implements both AES-256-CBC and ChaCha20 for symmetric encryption. RSA (2048-bit) is used for the secure exchange of symmetric keys.
  
- **Multi-Secured Handshake**  
  A robust handshake process that:
  1. Sends a handshake message from the server containing the chosen encryption algorithm and the server’s RSA public key.
  2. Receives an encrypted symmetric key from the client (encrypted with the server’s RSA key) along with the client’s RSA public key.
  3. Establishes a trusted channel once the server decrypts the symmetric key.
  
- **Dynamic Key Rotation**  
  Every 30 seconds (configurable), the application rotates the symmetric keys. A new key is generated and sent to all clients (encrypted with each client’s public key), and the server waits for an acknowledgment (ACK) from each client. In case of a timeout (5 seconds), a rollback to the previous key is performed.
  
- **Message Fragmentation and Reassembly**  
  Large messages and file transfers are split into multiple parts, which are transmitted over different channels and reassembled at the destination.
  
- **Heartbeat and Synchronization**  
  Regular heartbeat messages verify that all channels remain synchronized and healthy.

## Encryption Method Details

- **Asymmetric Encryption:**  
  - **Algorithm:** RSA (2048-bit)  
  - **Purpose:** Secure exchange of symmetric keys  
  - **Padding:** OAEP with MGF1 and SHA-256

- **Symmetric Encryption:** Two algorithms are available:
  - **AES-256-CBC:**  
    - Uses a random 16-byte IV  
    - Applies PKCS7 padding  
  - **ChaCha20:**  
    - Uses a 16-byte nonce
  
- **Message Integrity:**  
  Each plaintext message is prefixed with a constant marker ("MSG:") to verify correct decryption.

## Multi-Secured Handshake

1. **Server Initialization:**  
   The server generates an RSA key pair and listens on multiple ports.
2. **Handshake Message:**  
   Upon connection, the server sends a message containing the chosen encryption algorithm (AES-256-CBC or ChaCha20) and its RSA public key.
3. **Client Response:**  
   The client replies by sending a symmetric key (encrypted with the server’s RSA public key) and its own public RSA key.
4. **Key Establishment:**  
   The server decrypts the symmetric key and stores it along with the client’s public key, thus establishing a secure communication channel.

## Key Rotation Mechanism

- **Interval-Based Rotation:**  
  The system initiates key rotation every 30 seconds (configurable).
  
- **Procedure:**  
  1. A new symmetric key is generated.
  2. The key is encrypted with each client’s public RSA key.
  3. The new key is sent to every connected client.
  4. The server waits for an ACK from each client (with a 5-second timeout).
  5. If any client fails to acknowledge, a rollback to the previous key is initiated.
  6. A transitional phase of 10 seconds allows both old and new keys to be accepted before finalizing the rotation.

## Multi-Port and Multi-Protocol Communication

- **Multiple Ports:**  
  The application listens on several ports simultaneously to distribute the communication load.
  
- **Protocol Diversity:**  
  Based on the port index, different symmetric encryption algorithms (AES-256-CBC or ChaCha20) are employed, adding an extra layer of redundancy and security.
  
- **Parallel Processing:**  
  Message fragmentation allows parts of the same message to be sent in parallel, increasing both throughput and resilience.

## Performance and Security Considerations

- **Computation Time:**  
  The encryption and decryption operations (RSA, AES, and ChaCha20) are highly optimized and generally execute in milliseconds on modern hardware. Key rotation and handshake processes are designed to occur within the defined intervals (e.g., 30 seconds with a 10-second transitional phase).

- **Security Comparison:**  
  While the cryptographic primitives (RSA, AES-256, ChaCha20) meet modern security standards, the overall design (especially as implemented in Python) is experimental. It may exceed common commercial security standards but should not be assumed to meet military-grade requirements without further rigorous evaluation.

## Disclaimer

This project is a proof-of-concept and a thought experiment. Although it uses advanced cryptographic methods, it has not undergone extensive security audits. **Do not use this code for highly sensitive or mission-critical applications without further review and testing.** Contributions, feedback, and suggestions for improvements are highly welcome.

## Contributions

Feedback, ideas, and contributions to further enhance the security of this project are encouraged. Please open an issue or submit a pull request with your suggestions.

