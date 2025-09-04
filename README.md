Two-Party Secure Messaging App

A C++ desktop application that enables secure messaging between two systems over a network using AES (session key encryption) and RSA (public-private key pairs). The application is built with Qt (for GUI & networking) and Crypto++ (for cryptography).

Each instance of the app runs independently on a system with its own private key and the peer’s public key. Messages are encrypted with a fresh AES session key for each transmission, and the session key itself is encrypted with the recipient’s RSA public key.

🚀 Features

End-to-End Security

AES session key encryption for messages.

RSA encryption for securely sharing the session key.

Private key never leaves the local machine.

Graphical User Interface (Qt)

Connect Button → Establishes connection with the peer.

Input Textbox → Type your message.

Send Button → Encrypts & sends the message.

Display Window → Shows received messages (appends without overwriting).

Disconnect Button → Ends the connection.

Configuration File

Stores all parameters such as:

Local & peer IP addresses

Local & peer port numbers

RSA public/private key file paths

Cryptographic parameters (e.g., key sizes)

🛠 Tech Stack

Language: C++

GUI & Networking: Qt Framework

⚙️ How It Works

Key Setup

Each system stores its own private key and both public keys in the keys/ directory.

Keys must be pre-generated manually (using OpenSSL or similar).

Connection Establishment

User clicks Connect → the app uses the config file to find the peer’s IP & port.

Message Sending

User types a message → app generates a new AES session key.

Message is encrypted with AES.

Session key is encrypted with peer’s public key (RSA).

Both encrypted message + encrypted session key are sent to the peer.

Message Receiving

App receives encrypted message + encrypted session key.

Decrypts session key with private key (RSA).

Uses session key to decrypt the message (AES).

Displays the plaintext in the message window.

⚡ Installation & Setup
1. Prerequisites

C++17 or later

Qt 5/6 (for GUI & networking)

Crypto++ library installed

CMake (for building)
