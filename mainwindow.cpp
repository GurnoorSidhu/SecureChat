#include "mainwindow.h"
#include "cryptohelper.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDataStream>
#include <QBuffer>
#include <QDateTime>
#include <QStandardPaths>

#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    // Build UI
    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLay = new QVBoxLayout();

    display = new QPlainTextEdit();
    display->setReadOnly(true);
    display->setPlaceholderText("Received messages will appear here...");
    display->setMinimumHeight(300);

    input = new QPlainTextEdit();
    input->setPlaceholderText("Type message here...");
    input->setMaximumHeight(120);

    QHBoxLayout *btns = new QHBoxLayout();
    btnConnect = new QPushButton("Connect");
    btnDisconnect = new QPushButton("Disconnect");
    btnSend = new QPushButton("Send");

    btns->addWidget(btnConnect);
    btns->addWidget(btnDisconnect);
    btns->addStretch();
    btns->addWidget(btnSend);

    mainLay->addWidget(new QLabel("<b>Two-Party Secure Chat</b>"));
    mainLay->addWidget(display);
    mainLay->addWidget(input);
    mainLay->addLayout(btns);
    central->setLayout(mainLay);
    setCentralWidget(central);
    resize(700, 550);

    connect(btnConnect, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
    connect(btnDisconnect, &QPushButton::clicked, this, &MainWindow::onDisconnectClicked);
    connect(btnSend, &QPushButton::clicked, this, &MainWindow::onSendClicked);

    server = new QTcpServer(this);
    connect(server, &QTcpServer::newConnection, this, &MainWindow::onNewConnection);

    appendLog("UI ready.");
}

MainWindow::~MainWindow() {
    // Use close() and deleteLater to allow QObject cleanup
    if (socket) { socket->disconnectFromHost(); socket = nullptr; }
    if (client) { client->disconnectFromHost(); client = nullptr; }
    if (server && server->isListening()) server->close();
}

void MainWindow::appendLog(const QString &line) {
    QString t = QDateTime::currentDateTime().toString("[yyyy-MM-dd hh:mm:ss] ");
    display->appendPlainText(t + line);
}

bool MainWindow::loadConfig() {
    // You can change this path or use QStandardPaths::AppConfigLocation for portability.
    QString path = "/home/gurnoor/SecureChat/config.json";

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        appendLog("Failed to open config.json at " + path);
        return false;
    }

    QByteArray data = f.readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        appendLog("config.json invalid JSON object");
        return false;
    }

    QJsonObject obj = doc.object();

    localPort = static_cast<quint16>(obj.value("local_port").toInt());
    peerIp    = obj.value("peer_ip").toString();
    peerPort  = static_cast<quint16>(obj.value("peer_port").toInt());

    QString myPriv  = obj.value("my_private_key").toString();
    QString peerPub = obj.value("peer_public_key").toString();

    if (!CryptoHelper::loadPrivateKeyPEM(myPriv, myPrivate)) {
        appendLog("Failed to load private key: " + myPriv);
        return false;
    }

    if (!CryptoHelper::loadPublicKeyPEM(peerPub, peerPublic)) {
        appendLog("Failed to load peer public key: " + peerPub);
        return false;
    }

    appendLog("Config loaded. local_port=" + QString::number(localPort) +
              " peer=" + peerIp + ":" + QString::number(peerPort));
    return true;
}

void MainWindow::onConnectClicked() {
    if (!loadConfig()) return;

    // Start listening: try configured port, increment if in use
    if (!server->isListening()) {
        quint16 tryPort = localPort ? localPort : 40000;
        bool bound = false;
        while (tryPort <= 60000) { // avoid infinite loop
            if (server->listen(QHostAddress::Any, tryPort)) {
                localPort = tryPort;
                bound = true;
                break;
            }
            tryPort++;
        }

        if (!bound) {
            appendLog("Failed to bind any local port starting from " + QString::number(localPort));
            return;
        }

        appendLog("Listening on port " + QString::number(localPort));
    }

    // Try to connect out
    if (!client) {
        client = new QTcpSocket(this); // parented to MainWindow for predictable lifetime
        connect(client, &QTcpSocket::connected, this, &MainWindow::onSocketConnected);
        connect(client, &QTcpSocket::readyRead, this, &MainWindow::onSocketReadyRead);
        connect(client, &QTcpSocket::disconnected, this, &MainWindow::onSocketDisconnected);
        connect(client, &QObject::destroyed, this, &MainWindow::onSocketObjectDestroyed);

        client->connectToHost(peerIp, peerPort);
        appendLog("Attempting outgoing connection to " + peerIp + ":" + QString::number(peerPort));
    } else {
        if (client->state() != QAbstractSocket::ConnectedState) {
            client->connectToHost(peerIp, peerPort);
            appendLog("Attempting outgoing connection to " + peerIp + ":" + QString::number(peerPort));
        } else {
            appendLog("Already connected (outgoing)");
        }
    }
}

void MainWindow::onDisconnectClicked() {
    if (socket) {
        socket->disconnectFromHost();
        socket->close();
        socket = nullptr;
    }
    if (client) {
        client->disconnectFromHost();
        client->close();
        client = nullptr;
    }
    if (server && server->isListening()) server->close();
    rxBuffer.clear();
    appendLog("Disconnected and closed server.");
}

void MainWindow::onNewConnection() {
    QTcpSocket *ns = server->nextPendingConnection();
    if (!ns) return;

    appendLog("Accepted incoming connection from " + ns->peerAddress().toString() + ":" + QString::number(ns->peerPort()));

    // Re-parent to MainWindow for predictable lifetime (if not already)
    ns->setParent(this);

    // Always connect signals for this socket
    connect(ns, &QTcpSocket::readyRead, this, &MainWindow::onSocketReadyRead);
    connect(ns, &QTcpSocket::disconnected, this, &MainWindow::onSocketDisconnected);
    connect(ns, &QObject::destroyed, this, &MainWindow::onSocketObjectDestroyed);

    if (!socket) {
        socket = ns;
        appendLog("Using incoming connection as active socket");
    } else {
        appendLog("Already have active connection; closing extra incoming socket.");
        ns->disconnectFromHost();
        ns->close();
        ns->deleteLater();
    }
}

void MainWindow::onSocketConnected() {
    QTcpSocket *s = qobject_cast<QTcpSocket*>(sender());
    if (!s) return;
    appendLog("Outgoing connection established to " + s->peerAddress().toString() + ":" + QString::number(s->peerPort()));
    if (!socket) {
        socket = s;
    }
}

void MainWindow::onSocketDisconnected() {
    QTcpSocket *s = qobject_cast<QTcpSocket*>(sender());
    if (!s) return;

    if (s == socket) {
        appendLog("Active socket disconnected.");
        socket = nullptr;
    } else if (s == client) {
        appendLog("Outgoing client disconnected.");
        client = nullptr;
    }
    // rxBuffer may contain partial message for the next connection, clear to avoid confusion:
    rxBuffer.clear();
}

void MainWindow::onSocketObjectDestroyed(QObject* obj) {
    QTcpSocket *s = qobject_cast<QTcpSocket*>(obj);
    if (!s) return;
    if (s == socket) socket = nullptr;
    if (s == client) client = nullptr;
}

void MainWindow::onSendClicked() {
    QString text = input->toPlainText().trimmed();
    if (text.isEmpty()) return;
    if (!socket || socket->state() != QAbstractSocket::ConnectedState) {
        appendLog("No active connection. Press Connect first.");
        return;
    }
    sendPlainTextMessage(text);
    input->clear();
    appendLog("Sent (plaintext appended locally): " + text);
}

void MainWindow::sendPlainTextMessage(const QString &text) {
    if (!socket || socket->state() != QAbstractSocket::ConnectedState) {
        appendLog("Attempted to write but socket is not connected.");
        return;
    }

    using CryptoPP::SecByteBlock;
    std::string cipher;
    SecByteBlock key;
    std::string iv;

    // 1) AES-GCM encrypt with fresh key + 12-byte IV
    try {
        cipher = CryptoHelper::aesEncryptWithRandomKeyGCM(text.toStdString(), key, iv, 32);
        if (iv.size() != 12) {
            appendLog(QString("Unexpected IV size: %1").arg(iv.size()));
            return;
        }
    } catch (const CryptoPP::Exception &e) {
        appendLog("AES encryption failed: " + QString::fromStdString(e.what()));
        return;
    } catch (const std::exception &e) {
        appendLog("AES encryption failed: " + QString::fromStdString(e.what()));
        return;
    } catch (...) {
        appendLog("AES encryption failed: unknown error");
        return;
    }

    // 2) RSA-encrypt the AES key with peer's public key
    std::string encryptedKey;
    try {
        std::string keyStr(reinterpret_cast<const char*>(key.data()), key.size());
        encryptedKey = CryptoHelper::rsaEncrypt(peerPublic, keyStr);
        if (encryptedKey.empty()) {
            appendLog("RSA encryption produced empty key");
            return;
        }
    } catch (const CryptoPP::Exception &e) {
        appendLog("RSA encryption failed: " + QString::fromStdString(e.what()));
        return;
    } catch (const std::exception &e) {
        appendLog("RSA encryption failed: " + QString::fromStdString(e.what()));
        return;
    } catch (...) {
        appendLog("RSA encryption failed: unknown error");
        return;
    }

    // 3) Package with QDataStream ONLY (do NOT mix with QByteArray::append)
    QByteArray payload;
    {
        QDataStream out(&payload, QIODevice::WriteOnly);
        out.setByteOrder(QDataStream::BigEndian);

        // [u32 encKeyLen][encKey][u32 ivLen][iv][u32 cipherLen][cipher]
        out << static_cast<quint32>(encryptedKey.size());
        out.writeRawData(encryptedKey.data(), static_cast<int>(encryptedKey.size()));

        out << static_cast<quint32>(iv.size());
        out.writeRawData(iv.data(), static_cast<int>(iv.size()));

        out << static_cast<quint32>(cipher.size());
        out.writeRawData(cipher.data(), static_cast<int>(cipher.size()));
    }

    // 4) Frame with total length prefix
    const quint32 totalLen = static_cast<quint32>(payload.size());

    QByteArray message;
    {
        QDataStream header(&message, QIODevice::WriteOnly);
        header.setByteOrder(QDataStream::BigEndian);
        header << totalLen;
    }
    message.append(payload);

    qint64 written = socket->write(message);
    socket->flush();
    if (written <= 0) {
        appendLog("Failed to write message to socket.");
    }
}



void MainWindow::onSocketReadyRead() {
    QTcpSocket *s = qobject_cast<QTcpSocket*>(sender());
    if (!s) return;

    QByteArray data = s->readAll();
    if (data.isEmpty()) return;
    rxBuffer.append(data);

    // framing: first 4 bytes big-endian = totalLen (remaining)
    while (true) {
        if (rxBuffer.size() < 4)
            return; // need more data

        QDataStream ds(rxBuffer);
        ds.setByteOrder(QDataStream::BigEndian);
        quint32 totalLen = 0;
        ds >> totalLen;

        const quint32 MAX_MESSAGE = 10 * 1024 * 1024; // 10 MB cap
        if (totalLen == 0 || totalLen > MAX_MESSAGE) {
            appendLog("Received invalid message length; discarding buffer.");
            rxBuffer.clear();
            return;
        }

        if (static_cast<quint32>(rxBuffer.size()) < (4 + totalLen)) {
            // wait for full message
            return;
        }

        QByteArray body = rxBuffer.mid(4, totalLen);
        rxBuffer.remove(0, 4 + totalLen); // consume full frame

        // Manual parse of body
        const char *ptr = body.constData();
        int offset = 0;
        auto readU32 = [&](quint32 &out) -> bool {
            if (offset + 4 > body.size()) return false;
            quint32 v = ( (static_cast<unsigned char>(ptr[offset])   << 24) |
                          (static_cast<unsigned char>(ptr[offset+1]) << 16) |
                          (static_cast<unsigned char>(ptr[offset+2]) << 8)  |
                           static_cast<unsigned char>(ptr[offset+3]) );
            out = v;
            offset += 4;
            return true;
        };

        quint32 klen = 0, ivl = 0, clen = 0;
        if (!readU32(klen)) { appendLog("Malformed packet (klen). Discarding frame."); continue; }
        if (offset + static_cast<int>(klen) > body.size()) { appendLog("Malformed packet (key bytes). Discarding frame."); continue; }
        QByteArray encKey2 = body.mid(offset, klen);
        offset += klen;

        if (!readU32(ivl)) { appendLog("Malformed packet (ivl). Discarding frame."); continue; }
        if (offset + static_cast<int>(ivl) > body.size()) { appendLog("Malformed packet (iv bytes). Discarding frame."); continue; }
        QByteArray iv2 = body.mid(offset, ivl);
        offset += ivl;

        if (!readU32(clen)) { appendLog("Malformed packet (clen). Discarding frame."); continue; }
        if (offset + static_cast<int>(clen) > body.size()) { appendLog("Malformed packet (cipher bytes). Discarding frame."); continue; }
        QByteArray cipher2 = body.mid(offset, clen);
        offset += clen;

        // Optional: quick visibility for debugging
        appendLog(QString("Frame: klen=%1 iv=%2 clen=%3").arg(klen).arg(ivl).arg(clen));

        // Decrypt with hard guards to avoid crashes
        try {
            const quint32 MAX_RSA_ENC_KEY = 512; // up to 4096-bit RSA modulus
            const quint32 GCM_IV_LEN      = 12;
            const quint32 GCM_TAG_LEN     = 16;

            if (klen == 0 || klen > MAX_RSA_ENC_KEY) {
                appendLog(QString("Invalid RSA-encrypted key length: %1").arg(klen));
                continue;
            }
            if (ivl != GCM_IV_LEN) {
                appendLog(QString("Invalid IV length: %1 (expected %2)").arg(ivl).arg(GCM_IV_LEN));
                continue;
            }
            if (clen < GCM_TAG_LEN) {
                appendLog(QString("Cipher too short: %1").arg(clen));
                continue;
            }

            // RSA decrypt session key
            std::string encKeyStd(encKey2.constData(), static_cast<size_t>(encKey2.size()));
            std::string recoveredKey = CryptoHelper::rsaDecrypt(myPrivate, encKeyStd);
            if (recoveredKey.empty()) {
                appendLog("RSA decrypted key is empty");
                continue;
            }

            CryptoPP::SecByteBlock aesKey(
                reinterpret_cast<const CryptoPP::byte*>(recoveredKey.data()),
                recoveredKey.size()
            );

            // AES-GCM decrypt (ciphertext+tag) using 12-byte IV
            std::string cipherStd(cipher2.constData(), static_cast<size_t>(cipher2.size()));
            std::string ivStd(iv2.constData(), static_cast<size_t>(iv2.size()));

            std::string plain = CryptoHelper::aesDecryptWithKeyGCM(cipherStd, aesKey, ivStd);

            // Convert to QString safely (binary-safe)
            QString msg = QString::fromUtf8(plain.data(), static_cast<int>(plain.size()));
            appendLog("Received: " + msg);

        } catch (const CryptoPP::Exception &e) {
            appendLog("CryptoPP error during decryption: " + QString::fromStdString(e.what()));
            continue;
        } catch (const std::exception &e) {
            appendLog("Decryption failed: " + QString::fromStdString(e.what()));
            continue;
        } catch (...) {
            appendLog("Unknown error during decryption; skipping message.");
            continue;
        }
    } // while
}

