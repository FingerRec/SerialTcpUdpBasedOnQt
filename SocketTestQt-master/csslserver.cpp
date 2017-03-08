#include "csslserver.h"

QSsl::SslProtocol             CSSLServer::s_eSSLProtocol = QSsl::AnyProtocol;
QSslSocket::PeerVerifyMode    CSSLServer::s_eSSLVerifyMode = QSslSocket::VerifyNone;
QString                       CSSLServer::s_qstrCertFile;
QString                       CSSLServer::s_qstrKeyFile;

CSSLServer::CSSLServer(QObject* parent) :
    QTcpServer(parent),
    m_pClientSocket(0),
    m_pSSLServerByteArray(new QByteArray)
{
    connect(this, SIGNAL(SendSSLRcvdData(QByteArray)), parent, SLOT(ProcessSSLReceivedData(QByteArray)));
    connect(this, SIGNAL(SSLClientDisconnected()), parent, SLOT(onSSLClientDisconnected()));
    connect(this, SIGNAL(NewSSLClient(QSslSocket*)), parent, SLOT(onNewSSLClient(QSslSocket*)));
}

void CSSLServer::incomingConnection(qintptr iSocketDescriptor)
{
    // accept only one client in this version :
    if (m_pClientSocket)
        return;

    m_pClientSocket = new QSslSocket(this);

    if (m_pClientSocket->setSocketDescriptor(iSocketDescriptor))
    {
        emit NewSSLClient(m_pClientSocket);

        connect(m_pClientSocket, SIGNAL(readyRead()), this, SLOT(ServerReceivedData())); // append bytes in Log
        connect(m_pClientSocket, SIGNAL(disconnected()), this, SLOT(SSLClientDisconnect()));
        connect(m_pClientSocket, SIGNAL(sslErrors(const QList<QSslError> &)), this, SLOT(SSLErrorOccured(const QList<QSslError>&)));

        m_pClientSocket->setProtocol(s_eSSLProtocol);
        m_pClientSocket->setPeerVerifyMode(s_eSSLVerifyMode);

        /* Set the certificate and private key. */
        m_pClientSocket->setLocalCertificate(s_qstrCertFile);
        m_pClientSocket->setPrivateKey(s_qstrKeyFile);

        /* Start the server encryption process and wait for it to complete. */
        m_pClientSocket->startServerEncryption();

        // Add to the internal list of pending connections
        //addPendingConnection(m_pClientSocket);

        //m_pClientSocket->waitForEncrypted(); // test
        //tr("An error occurred: %1.").arg(m_pClientSocket->errorString());
    }
    else
    {
        SSLClientDisconnect();
    }
}

void CSSLServer::ServerReceivedData()
{
    QSslSocket* pSSLSocket = qobject_cast<QSslSocket*>(sender()); // which client has sent data
    if (pSSLSocket == 0)
        return;

    while (pSSLSocket->bytesAvailable() > 0)
    {
        m_pSSLServerByteArray->append(pSSLSocket->readAll());
        emit SendSSLRcvdData(*m_pSSLServerByteArray); // send a copy to GUI thread through a signal
        m_pSSLServerByteArray->remove(0, m_pSSLServerByteArray->size() );
    }
}

void CSSLServer::SSLErrorOccured(const QList<QSslError>& listErrors)
{
    listErrors; // unreferenced_parameter

    m_pClientSocket->ignoreSslErrors();
}

void CSSLServer::SSLClientDisconnect()
{
    m_pClientSocket->deleteLater(); // disconnect and free memory
    m_pClientSocket = 0;

    // inform GUI thread
    emit SSLClientDisconnected();
}

void CSSLServer::onSSLSendData(const QByteArray& packet)
{
    if (m_pClientSocket)
        m_pClientSocket->write(packet);
}

CSSLServer::~CSSLServer()
{
    delete m_pClientSocket;
    delete m_pSSLServerByteArray;
}
