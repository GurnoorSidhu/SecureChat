# 🔐 Two-Party Secure Messaging App

A **C++ desktop application** that enables **secure, end-to-end messaging** between two systems over a network using **AES (session key encryption)** and **RSA (public–private key pairs)**.

Built with **Qt** (for GUI & networking) and **Crypto++** (for cryptography).

---

## ✨ Features

* 🔒 **End-to-End Security**

  * AES session key encryption for messages.
  * RSA encryption for securely exchanging session keys.
  * Private keys **never leave the local machine**.

* 🖥️ **Graphical User Interface (Qt)**

  * **Connect** → Establishes connection with the peer.
  * **Send** → Encrypts & sends the message.
  * **Disconnect** → Ends the connection.
  * Message display window that **appends received messages** (no overwrite).

* ⚙️ **Configuration File**

  * Local & peer IP addresses
  * Local & peer port numbers
  * RSA key file paths
  * Cryptographic parameters (e.g., key sizes)

---

## 🛠 Tech Stack

* **Language**: C++17+
* **GUI & Networking**: [Qt 5/6](https://www.qt.io/)
* **Cryptography**: [Crypto++](https://cryptopp.com/)
* **Build System**: CMake

---

## ⚙️ How It Works

### 🔑 Key Setup

* Each instance stores:

  * Its own **private key**
  * Its own **public key**
  * The peer’s **public key**
* Keys must be **pre-generated manually** (using [OpenSSL](https://www.openssl.org/) or similar).

### 🔗 Connection Establishment

1. User clicks **Connect**.
2. The app reads peer IP & port from the **config file**.

### 📤 Sending a Message

1. User types a message.
2. App generates a **new AES session key**.
3. Message is encrypted with AES.
4. AES session key is encrypted with the **peer’s RSA public key**.
5. Encrypted message + encrypted session key are sent to the peer.

### 📥 Receiving a Message

1. App receives encrypted message + encrypted session key.
2. Decrypts the session key using **local RSA private key**.
3. Uses decrypted session key to decrypt the message (AES).
4. Displays plaintext in the GUI.

---

## ⚡ Installation & Setup

### 1. Prerequisites

* C++17 or later
* Qt 5/6
* Crypto++ library
* CMake

### 2. Clone the Repository

```bash
git clone https://github.com/your-username/secure-messaging-app.git
cd secure-messaging-app
```

### 3. Build the Project

```bash
mkdir build && cd build
cmake ..
make
```

### 4. Run

```bash
./SecureChat
```

---

## 📂 Project Structure

```
Directory structure:
└── gurnoorsidhu-securechat/
    ├── README.md
    ├── CMakeLists.txt
    ├── config.json
    ├── config2.json
    ├── cryptohelper.cpp
    ├── cryptohelper.h
    ├── main.cpp
    ├── mainwindow.cpp
    ├── mainwindow.cppZone.Identifier
    └── mainwindow.h

```

---

## 🔑 Generating RSA Keys (Example with OpenSSL)

```bash
# Generate private key
openssl genpkey -algorithm RSA -out local_private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in local_private.pem -out local_public.pem
```

Repeat for the peer system and exchange **public keys only**.

---

