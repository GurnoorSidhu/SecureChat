#pragma once

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTcpServer>
#include <QTcpSocket>
#include <QByteArray>
#include <QString>
#include <QJsonObject>

#include <cryptopp/rsa.h>

namespace CryptoPP { class RSA; }

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void onConnectClicked();
    void onDisconnectClicked();
    void onSendClicked();

    void onNewConnection();
    void onSocketConnected();
    void onSocketDisconnected();
    void onSocketReadyRead();
    void onSocketObjectDestroyed(QObject* obj);

private:
    void appendLog(const QString &line);
    bool loadConfig();
    void sendPlainTextMessage(const QString &text);

    // UI
    QPlainTextEdit *display = nullptr;
    QPlainTextEdit *input = nullptr;
    QPushButton *btnConnect = nullptr;
    QPushButton *btnDisconnect = nullptr;
    QPushButton *btnSend = nullptr;

    // Networking
    QTcpServer *server = nullptr;
    QTcpSocket *socket = nullptr; // active socket (incoming or outgoing)
    QTcpSocket *client = nullptr; // outgoing attempt socket (may be same as active)

    QByteArray rxBuffer;

    // Config / crypto
    quint16 localPort = 0;
    QString peerIp;
    quint16 peerPort = 0;

    CryptoPP::RSA::PrivateKey myPrivate;
    CryptoPP::RSA::PublicKey peerPublic;
};
