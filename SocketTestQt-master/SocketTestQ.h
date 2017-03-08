#ifndef SOCKETTESTQ_H
#define SOCKETTESTQ_H

#include <QtGui>
#include <QtNetwork>
#include <QtWidgets>
#include <QSslSocket>

#include "csslserver.h"
#include "tcpportlist.h"
#include "udpportlist.h"
//#include <QMainWindow>
#include <QDebug>
#include <QtSerialPort/QSerialPort>
#include <QtSerialPort/QSerialPortInfo>
#include <string>
#include <string.h>
#include <ChString.h>
namespace Ui {
class SocketTestQ;
}

class SocketTestQ : public QWidget
{
    Q_OBJECT

public:
    explicit SocketTestQ(QWidget *parent = 0);
    ~SocketTestQ();

    static QSsl::SslProtocol             s_eSSLProtocol;
    static QSslSocket::PeerVerifyMode    s_eSSLVerifyMode;
    static QString                       s_qstrCertFile;
    static QString                       s_qstrKeyFile; // musn't require a passphrase

private slots:
    // Client
    void on_uiClientConnectBtn_clicked();
    void on_uiClientSendMsgBtn_clicked();
    void on_uiClientMsg_returnPressed();
    void ClientReceivedData();
    void ClientConnected();
    void ClientDisconnected();
    void SocketError(QAbstractSocket::SocketError error);
    void ClientOpenFileNameDialog();
    void ClientSaveLogFile();
    void ClientClearLogFile();
    void ClientSendFile();
    void CheckSSLSupport();
    void SocketEncrypted();
    void SslErrors(const QList<QSslError>& listErrors);

    // Server
    void ServerListen();
    void NewClient();
    void ServerReceivedData();
    void ServerSendMsg();
    void ClientDisconnect(); // client disconnection
    void DisconnectClient();  // server kicks client
    void ServerOpenFileNameDialog();
    void ServerSaveLogFile();
    void ServerClearLogFile();
    void ServerSendFile();
    void WarnHex();
    void CheckSSLServerSetup();
    void PrivateKeyDialog();
    void CertDialog();

    void ShowTCPPortList();
    void ShowUDPPortList();

    // UDP
    void UDPListen();
    void UDPSendMsg();
    void UDPReceivedData();
    void UDPOpenFileNameDialog();
    void UDPSendFile();
    void UDPSaveLogFile();
    void UDPClearLogFile();

    //serial
    void on_clearButton_clicked();
    void on_sendButton_clicked();
    void on_openButton_clicked();
    void Read_Data();
    //hex to byte array ...etc
    QByteArray getByteArray(QString str);
    QString byteArrayToHexString(QString str);
    QByteArray hexStringToByte(QString hex);
// communication with CSSLServer
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();
    QString hexToAscall(QString);

    void on_pushButton_3_clicked();

public slots:
    void ProcessSSLReceivedData(QByteArray SSLByteArray);
    void onSSLClientDisconnected();
    void onNewSSLClient(QSslSocket*);

signals:
    void SendSSLData(const QByteArray&);
    void DisconnectSSLClient();

private:
    Ui::SocketTestQ *ui;
    TCPPortList m_TCPPortList;
    UDPPortList m_UDPPortList;
    //serial
    QSerialPort *serial;
    // Used by Server
    bool        m_bSecureServer;
    QTcpServer* m_Server;
    CSSLServer* m_pSecureServer;
    QTcpSocket* m_ClientSocket;
    //QHash<QTcpSocket*,QByteArray*> m_ClientSockets; // for a future version ;) a client list will be dynamically created
    QByteArray* m_ServerByteArray;

    // Used by Client
    bool        m_bSecure;
    QString     m_qstrCipher;
    QSslSocket* m_ServerSocket; // QSslSocket can behave as a normal QTcpSocket with no overhead
    QByteArray* m_ClientByteArray;

    // Used by UDP
    QUdpSocket* m_UDPSocket;
    QByteArray* m_UDPByteArray;

    //bool for uid and anti
    //int count = 0;
    bool click_uid = false;
    bool click_anti = false;
    bool click_sqa = false;
    QString str2 = "";

    //select uid and anti
};

#endif // SOCKETTESTQ_H
