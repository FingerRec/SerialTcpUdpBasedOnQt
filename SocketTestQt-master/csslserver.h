#ifndef CSSLSERVER_H
#define CSSLSERVER_H

#include <QtNetwork>
#include <QSslSocket>

class CSSLServer /*finale*/ : public QTcpServer
{
    Q_OBJECT

public:
    CSSLServer(QObject* parent = NULL);
    ~CSSLServer() /*override*/;

    //CSSLServer(const CSSLServer&) = delete;
    //CSSLServer& operator=(const CSSLServer&) = delete;

    static QSsl::SslProtocol             s_eSSLProtocol;
    static QSslSocket::PeerVerifyMode    s_eSSLVerifyMode;
    static QString                       s_qstrCertFile;
    static QString                       s_qstrKeyFile; // musn't require a passphrase

signals:
    void SendSSLRcvdData(QByteArray);
    void SSLClientDisconnected();
    void NewSSLClient(QSslSocket*);

protected:
    /* invoked when an incoming connection is received by the server */
    void incomingConnection(qintptr iSocketDescriptor) override;

public slots:
    void SSLClientDisconnect();
    void onSSLSendData(const QByteArray&);

private slots:
    void SSLErrorOccured(const QList<QSslError>&);
    void ServerReceivedData();

private:
    QSslSocket*    m_pClientSocket;
    QByteArray*    m_pSSLServerByteArray;
};

#endif // CSSLSERVER_H
