#include "SocketTestQ.h"
#include "ui_SocketTestQ.h"
#include <qdebug.h>
#include <QtSerialPort/QSerialPort>
#include <QtSerialPort/QSerialPortInfo>
#include <QtGui/QApplicationStateChangeEvent>
#define MAX_HOSTNAME_LENGTH     255

//used for stm32 type-a card, you can change it to your card command
static const char sel_uid[] = {0x26,0x3f,0x3b};
static const char sel_anti[] = {0x93,0x20,0x3f,0x3b};
static const char sel_sqa[] = {0x93,0x70,0x3f,0x3b};

#define my_delete(x) {delete x; x = 0;}


QSsl::SslProtocol             SocketTestQ::s_eSSLProtocol = QSsl::AnyProtocol;
QSslSocket::PeerVerifyMode    SocketTestQ::s_eSSLVerifyMode = QSslSocket::VerifyNone;
QString                       SocketTestQ::s_qstrCertFile;
QString                       SocketTestQ::s_qstrKeyFile;

SocketTestQ::SocketTestQ(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SocketTestQ),
    m_bSecure(false), // client
    m_bSecureServer(false)
{
    // ************** Miscellaneous
    // **************
    ui->setupUi(this);
    setFixedSize(geometry().width(),geometry().height());
    //setWindowTitle(tr("SocketTestQ v 1.0.0"));

    // ************** Server
    // **************
    m_Server = new QTcpServer(this);
    m_pSecureServer = new CSSLServer(this);
    m_ClientSocket = 0;
    m_ServerByteArray = new QByteArray();

    // Connection between signals and slots of buttons
    connect(ui->uiServerListenBtn, SIGNAL(clicked()), this, SLOT(ServerListen()));
    connect(ui->uiServerPortListBtn, SIGNAL(clicked()), this, SLOT(ShowTCPPortList()));

    connect(ui->uiServerSendMsgBtn, SIGNAL(clicked()), this, SLOT(ServerSendMsg()));
    connect(ui->uiServerBrowseBtn, SIGNAL(clicked()), this, SLOT(ServerOpenFileNameDialog()));
    connect(ui->uiServerSendFileBtn, SIGNAL(clicked()), this, SLOT(ServerSendFile()));

    connect(ui->uiServerSaveLogBtn, SIGNAL(clicked()), this, SLOT(ServerSaveLogFile()));
    connect(ui->uiServerClearLogBtn, SIGNAL(clicked()), this, SLOT(ServerClearLogFile()));
    connect(ui->uiServerDisconnectBtn, SIGNAL(clicked()), this, SLOT(DisconnectClient()));
    connect(ui->uiServerRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
    connect(ui->uiServerSecure, SIGNAL(clicked()), this, SLOT(CheckSSLServerSetup()));
    connect(ui->uiBtnLoadKey, SIGNAL(clicked()), this, SLOT(PrivateKeyDialog()));
    connect(ui->uiBtnLoadCert, SIGNAL(clicked()), this, SLOT(CertDialog()));

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_Server, SIGNAL(newConnection()), this, SLOT(NewClient()));
    // SSL
    connect(this, SIGNAL(DisconnectSSLClient()), m_pSecureServer, SLOT(SSLClientDisconnect()));
    connect(this, SIGNAL(SendSSLData(const QByteArray&)), m_pSecureServer, SLOT(onSSLSendData(const QByteArray&)));

    // ************** Client
    // ************** autoconnect has been used for a few client's widgets
    m_ServerSocket = new QSslSocket(this);
    m_ServerSocket->setPeerVerifyMode(QSslSocket::VerifyNone);
    m_ClientByteArray = new QByteArray();

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_ServerSocket, SIGNAL(readyRead()), this, SLOT(ClientReceivedData()));
    connect(m_ServerSocket, SIGNAL(connected()), this, SLOT(ClientConnected()));
    connect(m_ServerSocket, SIGNAL(disconnected()), this, SLOT(ClientDisconnected()));
    connect(m_ServerSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(SocketError(QAbstractSocket::SocketError)));
    /* used only in Secure Mode */
    connect(m_ServerSocket, SIGNAL(encrypted()), this, SLOT(SocketEncrypted()));
    connect(m_ServerSocket, SIGNAL(sslErrors(const QList<QSslError>&)), this, SLOT(SslErrors(const QList<QSslError>&)));

    // Connection between signals and slots of buttons
    connect(ui->uiClientPortListBtn, SIGNAL(clicked()), this, SLOT(ShowTCPPortList()));
    connect(ui->uiClientRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
    connect(ui->uiClientBrowseBtn, SIGNAL(clicked()), this, SLOT(ClientOpenFileNameDialog()));
    connect(ui->uiClientSendFileBtn, SIGNAL(clicked()), this, SLOT(ClientSendFile()));
    connect(ui->uiClientSaveLogBtn, SIGNAL(clicked()), this, SLOT(ClientSaveLogFile()));
    connect(ui->uiClientClearLogBtn, SIGNAL(clicked()), this, SLOT(ClientClearLogFile()));
    connect(ui->uiClientSecureCheck, SIGNAL(clicked()), this, SLOT(CheckSSLSupport()));

    // ************** UDP
    // **************
    m_UDPSocket = new QUdpSocket(this);
    m_UDPByteArray = new QByteArray();

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_UDPSocket, SIGNAL(readyRead()), this, SLOT(UDPReceivedData()));

    // Connection between signals and slots of buttons
    connect(ui->uiUdpServerListenBtn, SIGNAL(clicked()), this, SLOT(UDPListen()));
    connect(ui->uiUdpSendMsgBtn, SIGNAL(clicked()), this, SLOT(UDPSendMsg()));
    connect(ui->uiUdpBrowseBtn, SIGNAL(clicked()), this, SLOT(UDPOpenFileNameDialog()));
    connect(ui->uiUdpSendFileBtn, SIGNAL(clicked()), this, SLOT(UDPSendFile()));
    connect(ui->uiUdpSaveLogBtn, SIGNAL(clicked()), this, SLOT(UDPSaveLogFile()));
    connect(ui->uiUdpClearLogBtn, SIGNAL(clicked()), this, SLOT(UDPClearLogFile()));
    connect(ui->uiUdpServerPortListBtn, SIGNAL(clicked()), this, SLOT(ShowUDPPortList()));
    connect(ui->uiUdpClientPortListBtn, SIGNAL(clicked()), this, SLOT(ShowUDPPortList()));
    connect(ui->uiUdpRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));


    //server
    //查找可用的串口
    foreach(const QSerialPortInfo &info, QSerialPortInfo::availablePorts())
    {
        QSerialPort serial;
        serial.setPort(info);
        if(serial.open(QIODevice::ReadWrite))
        {
            ui->PortBox->addItem(serial.portName());
            serial.close();
        }
    }
    //设置波特率下拉菜单默认显示第三项
    ui->BaudBox->setCurrentIndex(5);
    //关闭发送按钮的使能
    ui->sendButton->setEnabled(false);
    qDebug() << tr("界面设定成功");
}

// ************** Server
// **************

void SocketTestQ::ServerListen()
{
    ui->uiServerSecure->setEnabled(false);
    m_bSecureServer = (ui->uiServerSecure->isChecked()) ? true : false;
    QTcpServer* pCurrentServer = (m_bSecureServer) ? m_pSecureServer : m_Server;

    if(pCurrentServer->isListening())
    {
        pCurrentServer->close();
        ui->uiServerListenBtn->setText( tr("Start Listening") );
        (!m_bSecureServer) ? ui->uiServerLog->append(tr("Server stopped"))
                           : ui->uiServerLog->append(tr("SSL Server stopped"));
        ui->uiServerSecure->setEnabled(true);
        return;
    }

    if((ui->uiServerIP->text()).length() <= MAX_HOSTNAME_LENGTH )
    {
        QHostAddress ServerAddress(ui->uiServerIP->text()); // if this ctor is not explicit, we can put the text directly on listen()

        if ( !pCurrentServer->listen(ServerAddress, ui->uiServerPort->value() ) )
        {
            QMessageBox::critical(this, (m_bSecureServer) ? tr("Secure Server Error") : tr("Server Error"),
                                        tr("Server couldn't start. Reason :<br />") + pCurrentServer->errorString());
            ui->uiServerSecure->setEnabled(true);
        }
        else
        {
            ui->uiServerListenBtn->setText( tr("Stop Listening") );
            ui->uiServerLog->append((m_bSecureServer) ? tr("Secure Server Started\r\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~") :
                                                        tr("Server Started\r\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
        }
    }
    else
    {
        QMessageBox::critical(this, (m_bSecureServer) ? tr("Secure TCP Server Error") : tr("TCP Server Error"),
                                    tr("IP address / hostname is too long !"));
        ui->uiServerSecure->setEnabled(true);
    }
}

void SocketTestQ::NewClient()
{
    if(!m_ClientSocket && m_Server->hasPendingConnections() ) // we accept only one client in version 1.0.0
    {
        m_ClientSocket = m_Server->nextPendingConnection();

        connect(m_ClientSocket, SIGNAL(readyRead()), this, SLOT(ServerReceivedData())); // append bytes in Log
        connect(m_ClientSocket, SIGNAL(disconnected()), this, SLOT(ClientDisconnect()));

        ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < ") + (m_ClientSocket->peerAddress()).toString() +tr(" >") );

        //ui->uiServerLog->append(tr("New Client: ") + m_ClientSocket->peerName()); // empty
        ui->uiServerLog->append(tr("New Client addr: ") + (m_ClientSocket->peerAddress()).toString());

        ui->uiServerSendMsgBtn->setEnabled(true);
        ui->uiServerSendFileBtn->setEnabled(true);
        ui->uiServerBrowseBtn->setEnabled(true);
        ui->uiServerDisconnectBtn->setEnabled(true);
    }
}

void SocketTestQ::ClientDisconnect()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // similar to dynamic_cast
    if (socket == 0)
        return;

    socket->deleteLater();
    ui->uiServerSendMsgBtn->setEnabled(false);
    ui->uiServerSendFileBtn->setEnabled(false);
    ui->uiServerBrowseBtn->setEnabled(false);
    ui->uiServerDisconnectBtn->setEnabled(false);
    m_ClientSocket = 0;
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
    ui->uiServerLog->append(tr("Client closed conection."));
}

void SocketTestQ::DisconnectClient()
{
    if(!m_bSecureServer)
    {
        if (m_ClientSocket)
        {
            m_ClientSocket->deleteLater();
            ui->uiServerSendMsgBtn->setEnabled(false);
            ui->uiServerSendFileBtn->setEnabled(false);
            ui->uiServerBrowseBtn->setEnabled(false);
            ui->uiServerDisconnectBtn->setEnabled(false);
            m_ClientSocket = 0;
            ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
            ui->uiServerLog->append(tr("Server closed client connection."));
        }
        return;
    }

    // SSL
    emit DisconnectSSLClient();
}

// TODO : store rcvd data in a file for next version
void SocketTestQ::ServerReceivedData()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    while (socket->bytesAvailable() > 0)
    {
        m_ServerByteArray->append(socket->readAll());
        if(ui->uiServerRadioHex->isChecked())
        {
            ui->uiServerLog->append(QString(m_ServerByteArray->toHex())); // TODO : make it more pretty to the user (tpUpper+separated symbols)
        }
        else
        {
            ui->uiServerLog->append(QString(*m_ServerByteArray));
        }
        m_ServerByteArray->remove(0, m_ServerByteArray->size() );
    }
}

void SocketTestQ::WarnHex()
{
    QMessageBox::warning(this, tr("Hex mode"), tr("Experimental feature. Please send me your suggestion."));
}

void SocketTestQ::ServerSendMsg()
{
    QByteArray packet;

    if (ui->uiServerRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiServerMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiServerMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiServerMsg->text().toUtf8().at(c) );

        if (ui->uiServerRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiServerRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    if (!m_bSecureServer)
        m_ClientSocket->write(packet);
    else
        emit SendSSLData(packet);

    (!m_bSecureServer) ? ui->uiServerLog->append("[=>] : " + ui->uiServerMsg->text())
                       : ui->uiServerLog->append("[Encrypted =>] : " + ui->uiServerMsg->text());
    ui->uiServerMsg->setText("");
}

void SocketTestQ::ServerOpenFileNameDialog()
{
    ui->uiServerFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::ServerSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiServerLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::ServerClearLogFile()
{
    ui->uiServerLog->clear();
}

void SocketTestQ::ShowTCPPortList()
{
    m_TCPPortList.show();
}

void SocketTestQ::ShowUDPPortList()
{
    m_UDPPortList.show();
}

void SocketTestQ::ServerSendFile()
{
    if(ui->uiServerFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiServerFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        if (!m_bSecureServer)
            m_ClientSocket->write(packet);
        else
            emit SendSSLData(packet);

        file.close();
        (!m_bSecureServer) ? ui->uiServerLog->append("[=>] File was sent to connected client.")
                           : ui->uiServerLog->append("[=>] File was sent to connected SSL client.");
    }
}

/******** Client ********/

// Connection attempt to a server
void SocketTestQ::on_uiClientConnectBtn_clicked()
{
    //bool bUnconnected = !m_ServerSocket || m_ServerSocket->state() == QAbstractSocket::UnconnectedState;
    bool bConnected = m_ServerSocket->state() == QAbstractSocket::ConnectedState; // no need to check for nullptr.
    if (bConnected) // m_ServerSocket->isOpen()
    {
        m_ServerSocket->close();
        return;
    }

    m_bSecure = (ui->uiClientSecureCheck->isChecked()) ? true : false;

    ui->uiClientLog->append(tr("<em>Attempting to connect...</em>"));

    m_ServerSocket->abort(); // disable previous connections if they exist

    if (m_bSecure)
    {
        m_ServerSocket->setProtocol(s_eSSLProtocol);
        m_ServerSocket->setPeerVerifyMode(s_eSSLVerifyMode);

        /* Set the certificate and private key. */
        m_ServerSocket->setLocalCertificate(s_qstrCertFile);
        m_ServerSocket->setPrivateKey(s_qstrKeyFile);

        /* connection to the requested SSL/TLS server */
        m_ServerSocket->connectToHostEncrypted(ui->uiClientDstIP->text(), ui->uiClientDstPort->value());
    }
    else
    {
        /* connection to the requested unencrypted server */
        m_ServerSocket->connectToHost(ui->uiClientDstIP->text(), ui->uiClientDstPort->value());
    }
}

void SocketTestQ::SocketEncrypted()
{
    if (!m_bSecure)
        return;

    QSslSocket* pSocket = qobject_cast<QSslSocket*>(m_ServerSocket);
    if (pSocket == 0)
        return; // or might have disconnected already

    // get the peer's certificate
    //QSslCertificate certCli = pSocket->peerCertificate();

    QSslCipher ciph = pSocket->sessionCipher();
    m_qstrCipher = QString("%1, %2 (%3/%4)").arg(ciph.authenticationMethod())
                     .arg(ciph.name()).arg(ciph.usedBits()).arg(ciph.supportedBits());

    ui->uiClientGroupBoxConnection->setTitle( tr("Connected To < ") + (m_ServerSocket->peerAddress()).toString()
                                              + ((m_bSecure) ? (tr(" > Cipher : ") + m_qstrCipher) : tr(" > Unencrypted")) );
}

void SocketTestQ::SslErrors(const QList<QSslError>& listErrors)
{
    listErrors; // unreferenced_parameter

    m_ServerSocket->ignoreSslErrors();
}

// Sending msg to server
void SocketTestQ::on_uiClientSendMsgBtn_clicked()
{
    QByteArray packet;

    if (ui->uiClientRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiClientMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiClientMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiClientMsg->text().toUtf8().at(c) );

        if (ui->uiClientRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiClientRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    m_ServerSocket->write(packet);

    ui->uiClientLog->append("[=>] : " + ui->uiClientMsg->text());
    ui->uiClientMsg->clear();
    ui->uiClientMsg->setFocus(); // set the focus inside it
}

// Pressing "Enter" has the same effect than clicking on "Send" button
void SocketTestQ::on_uiClientMsg_returnPressed()
{
    on_uiClientSendMsgBtn_clicked();
}

// packet received or a sub-packet
void SocketTestQ::ClientReceivedData()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    while (socket->bytesAvailable() > 0)
    {
        m_ClientByteArray->append(socket->readAll());
        if(ui->uiClientRadioHex->isChecked())
        {
            ui->uiClientLog->append(QString(m_ClientByteArray->toHex()));
        }
        else
        {
            ui->uiClientLog->append(QString(*m_ClientByteArray));
        }
        m_ClientByteArray->remove(0, m_ClientByteArray->size() );
    }
}

// this slot gets called when the connection to the remote destination has succeeded.
void SocketTestQ::ClientConnected()
{
    ui->uiClientLog->append(tr("<em>Connected !</em>"));
    ui->uiClientConnectBtn->setText(tr("Disconnect"));
    if (!m_bSecure)
        ui->uiClientGroupBoxConnection->setTitle(tr("Connected To < ") + (m_ServerSocket->peerAddress()).toString() +tr(" >"));
    ui->uiClientSendMsgBtn->setEnabled(true);
    ui->uiClientSendFileBtn->setEnabled(true);
    ui->uiClientBrowseBtn->setEnabled(true);
}

// this slot gets called when the client gets disconnected
void SocketTestQ::ClientDisconnected()
{
    ui->uiClientGroupBoxConnection->setTitle(tr("Connected to < NONE >"));
    ui->uiClientConnectBtn->setText(tr("Connect"));
    ui->uiClientSendMsgBtn->setEnabled(false);
    ui->uiClientSendFileBtn->setEnabled(false);
    ui->uiClientBrowseBtn->setEnabled(false);
}

// this slot gets called when there is a socket related error
void SocketTestQ::SocketError(QAbstractSocket::SocketError error)
{
    switch(error) // On affiche un message diff茅rent selon l'erreur qu'on nous indique
    {
        case QAbstractSocket::HostNotFoundError:
            QMessageBox::critical(this, tr("Opening connection"), tr("Connection refused, server not found, check IP and Port "));
            break;
        case QAbstractSocket::ConnectionRefusedError:
            QMessageBox::critical(this, tr("Opening connection"), tr("Connection refused, server refused the connection, check IP and Port and that server is available"));
            break;
        case QAbstractSocket::RemoteHostClosedError:
            QMessageBox::warning(this, tr("Disconnected"), tr("Server closed the connection "));
            break;
        default:
            QMessageBox::critical(this, tr("Information"), tr("<em>ERROR : ") + m_ServerSocket->errorString() + tr("</em>"));
    }

    ui->uiClientConnectBtn->setText(tr("Connect"));
}

void SocketTestQ::ClientOpenFileNameDialog()
{
    ui->uiClientFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::ClientSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiClientLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::ClientClearLogFile()
{
    ui->uiClientLog->clear();
}

void SocketTestQ::ClientSendFile()
{
    if(ui->uiClientFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiClientFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        m_ServerSocket->write(packet);

        file.close();
        ui->uiClientLog->append("[=>] File was sent to server.");
    }
}

/******** UDP ********/

void SocketTestQ::UDPListen()
{
    if(m_UDPSocket->state() != QAbstractSocket::UnconnectedState)
    {
        m_UDPSocket->close();
        ui->uiUdpServerListenBtn->setText( tr("Start Listening") );
        ui->uiUdpLog->append(tr("UDP Server stopped"));
        return;
    }

    if((ui->uiServerIP->text()).length() <= MAX_HOSTNAME_LENGTH )
    {
        QHostAddress ServerAddress(ui->uiUdpServerIp->text());

        if ( !m_UDPSocket->bind(ServerAddress,ui->uiUdpServerPort->value()) )
        {
            QMessageBox::critical(this, tr("UDP Server Error"), tr("UDP server couldn't start. Reason :<br />") + m_UDPSocket->errorString());
        }
        else
        {
            ui->uiUdpServerListenBtn->setText( tr("Stop Listening") );
            ui->uiUdpLog->append(tr("Server Started on Port : ") + QString::number(ui->uiUdpServerPort->value()));
        }
    }
    else
    {
        QMessageBox::critical(this, tr("UDP Server Error"), tr("IP address / hostname is too long !"));
    }
}

void SocketTestQ::UDPSendMsg()
{
    QByteArray packet;

    if (ui->uiUdpRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiUdpMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiUdpMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiUdpMsg->text().toUtf8().at(c) );

        if (ui->uiUdpRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiUdpRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    m_UDPSocket->writeDatagram(packet, QHostAddress(ui->uiUdpClientIp->text()), ui->uiUdpClientPort->value());

    ui->uiUdpLog->append("[=>] : " + ui->uiUdpMsg->text());
    ui->uiUdpMsg->clear();
}

void SocketTestQ::UDPSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiUdpLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::UDPClearLogFile()
{
    ui->uiUdpLog->clear();
}

void SocketTestQ::UDPOpenFileNameDialog()
{
    ui->uiUdpFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::UDPSendFile()
{
    if(ui->uiUdpFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiUdpFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        m_UDPSocket->writeDatagram(packet, QHostAddress(ui->uiUdpClientIp->text()), ui->uiUdpClientPort->value());

        file.close();
        ui->uiUdpLog->append("[=>] File was sent.");
    }
}

void SocketTestQ::UDPReceivedData()
{
    QUdpSocket *socket = qobject_cast<QUdpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    m_UDPByteArray->resize(socket->pendingDatagramSize());

    QHostAddress sender;
    quint16 senderPort;

    socket->readDatagram(m_UDPByteArray->data(), m_UDPByteArray->size(), &sender, &senderPort);

    if(ui->uiUdpRadioHex->isChecked())
    {
        ui->uiUdpLog->append(QString(m_UDPByteArray->toHex()));
    }
    else
    {
        ui->uiUdpLog->append(QString(*m_UDPByteArray));
    }

    m_UDPByteArray->remove(0, m_UDPByteArray->size() );
}

SocketTestQ::~SocketTestQ()
{
    delete ui;
    delete m_ServerByteArray;
    delete m_Server;
    delete m_ServerSocket;
    delete m_ClientByteArray;
  //  if(serial) delete serial;

}

void SocketTestQ::CheckSSLSupport()
{
    if (!QSslSocket::supportsSsl())
    {
        QMessageBox::information(0, "Secure Socket Client",
                                    "This system does not support OpenSSL.");

        ui->uiClientSecureCheck->setEnabled(false);
        ui->uiClientSecureCheck->setChecked(false);

        return;
    }

    // enryption files are not mandatory for an SSL/TLS client.
    s_qstrKeyFile = ui->uiKeyFileCli->text();
    s_qstrCertFile = ui->uiCertFileCli->text();

    switch (ui->uiCBProtocolCli->currentIndex())
    {
        default:
        case 0:
            s_eSSLProtocol = QSsl::AnyProtocol; // auto: SSLv2, SSLv3, or TLSv1.0
            break;
        case 1: // SSLv2
            s_eSSLProtocol = QSsl::SslV2;
            break;
        case 2: // SSLv3
            s_eSSLProtocol = QSsl::SslV3;
            break;
        case 3: // TLSv1.0
            s_eSSLProtocol = QSsl::TlsV1_0;
            break;
    }

    switch (ui->uiCBVerifyModeCli->currentIndex())
    {
        default:
        case 0:
            s_eSSLVerifyMode = QSslSocket::VerifyNone;
            break;
        case 1:
            s_eSSLVerifyMode = QSslSocket::QueryPeer;
            break;
        case 2:
            s_eSSLVerifyMode = QSslSocket::VerifyPeer;
            break;
        case 3:
            s_eSSLVerifyMode = QSslSocket::AutoVerifyPeer;
            break;
    }
}

void SocketTestQ::CheckSSLServerSetup()
{
    if (!QSslSocket::supportsSsl())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "This system does not support OpenSSL.");

        ui->uiServerSecure->setEnabled(false);
        ui->uiServerSecure->setChecked(false);
        return;
    }

    // Check if the required files's paths are indicated and warn user if there's a problem...
    if (ui->uiKeyFile->text().isEmpty())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "You didn't indicate private key's file path. Go to SSL Settings.");
        ui->uiServerSecure->setChecked(false);
        return;
    }
    CSSLServer::s_qstrKeyFile = ui->uiKeyFile->text();

    if (ui->uiCertFile->text().isEmpty())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "You didn't indicate server's certificate file path. Go to SSL Settings.");
        ui->uiServerSecure->setChecked(false);
        return;
    }
    CSSLServer::s_qstrCertFile = ui->uiCertFile->text();

    switch (ui->uiCBProtocol->currentIndex())
    {
        default:
        case 0:
            /* The socket understands SSLv2, SSLv3, and TLSv1.0.
             * This value is used by QSslSocket only.*/
            CSSLServer::s_eSSLProtocol = QSsl::AnyProtocol;
            break;
        case 1: // SSLv2
            CSSLServer::s_eSSLProtocol = QSsl::SslV2;
            break;
        case 2: // SSLv3
            CSSLServer::s_eSSLProtocol = QSsl::SslV3;
            break;
        case 3: // TLSv1.0
            CSSLServer::s_eSSLProtocol = QSsl::TlsV1_0;
            break;
    }

    switch (ui->uiCBVerifyMode->currentIndex())
    {
        /* QSslSocket will not request a certificate from the peer.
         * You can set this mode if you are not interested in the identity of the other side of the connection.
         * The connection will still be encrypted, and your socket will still send its local certificate
         * to the peer if it's requested.
         */
        default:
        case 0:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::VerifyNone;
            break;

        /* QSslSocket will request a certificate from the peer, but does not require this certificate to be valid.
         * This is useful when you want to display peer certificate details to the user without affecting
         * the actual SSL handshake.
         * This mode is the default for servers.
         */
        case 1:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::QueryPeer;
            break;

        /* QSslSocket will request a certificate from the peer during the SSL handshake phase, and requires
         * that this certificate is valid. On failure, QSslSocket will emit the QSslSocket::sslErrors() signal.
         * This mode is the default for clients.
         */
        case 2:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::VerifyPeer;
            break;

        /* QSslSocket will automatically use QueryPeer for server sockets and VerifyPeer for client sockets.
         */
        case 3:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::AutoVerifyPeer;
            break;
    }
}

void SocketTestQ::PrivateKeyDialog()
{
    ui->uiKeyFile->setText(QFileDialog::getOpenFileName(this, tr("Choose a private key file"), QString(), "*.*"));
}

void SocketTestQ::CertDialog()
{
    ui->uiCertFile->setText(QFileDialog::getOpenFileName(this, tr("Choose a certificate file"), QString(), "*.*"));
}

void SocketTestQ::ProcessSSLReceivedData(QByteArray SSLByteArray)
{
    if(ui->uiServerRadioHex->isChecked())
    {
        ui->uiServerLog->append(QString(SSLByteArray.toHex()));
    }
    else
    {
        ui->uiServerLog->append(QString(SSLByteArray));
    }
}

void SocketTestQ::onSSLClientDisconnected()
{
    ui->uiServerSendMsgBtn->setEnabled(false);
    ui->uiServerSendFileBtn->setEnabled(false);
    ui->uiServerBrowseBtn->setEnabled(false);
    ui->uiServerDisconnectBtn->setEnabled(false);
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
    ui->uiServerLog->append(tr("SSL Client closed conection."));
}

void SocketTestQ::onNewSSLClient(QSslSocket* pSocket)
{
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected SSL Client : < ") + (pSocket->peerAddress()).toString() +tr(" >") );
    ui->uiServerLog->append(tr("New SSL Client addr: ") + (pSocket->peerAddress()).toString());
    ui->uiServerSendMsgBtn->setEnabled(true);
    ui->uiServerSendFileBtn->setEnabled(true);
    ui->uiServerBrowseBtn->setEnabled(true);
    ui->uiServerDisconnectBtn->setEnabled(true);
}




//clean
void SocketTestQ::on_clearButton_clicked()
{
    ui->textEdit->clear();
    ui->lineEdit->clear();
    ui->textEdit_4->clear();
    ui->textEdit_2->clear();
    ui->textEdit_3->clear();
}

//send data,to hex
void SocketTestQ::on_sendButton_clicked()
{
    //QString temp = hexToAscall(ui->textEdit_2->toPlainText());
   // serial->write(temp.toLatin1());
    QByteArray temp = hexStringToByte(ui->textEdit_2->toPlainText());
    serial->write(temp);
    qDebug() <<"string is:" <<ui->textEdit_2->toPlainText();
    qDebug() << "byte array is:"<<temp;
 }

//read the data
void SocketTestQ::Read_Data()
{
    QByteArray buf;
    buf = serial->readAll();
    //byte array
    if(!buf.isEmpty())
    {
        QString str = ui->textEdit->toPlainText();
        str += buf.toHex();
        QString str2 = ui->textEdit_4->toPlainText();
        str2 += buf.toHex();
        ui->textEdit->clear();
     //   ui->textEdit_4->clear();
        if(click_uid)
        {
            //clear first
            ui->lineEdit->clear();
            ui->lineEdit->setText(str);
            click_uid = false;
        }
        else if(click_anti)
        {
            ui->textEdit_4->clear();
            ui->textEdit_4->append(str2);
            if((ui->textEdit_4->toPlainText()).length() == 10) click_anti = false;
        }
        else if(click_sqa)
        {
            ui->textEdit_3->clear();
            ui->textEdit_3->append(str);
            click_sqa = false;
        }
        else  ui->textEdit->append(str);
    }
    buf.clear();
}

//open the serial
void SocketTestQ::on_openButton_clicked()
{
    if(ui->openButton->text()==tr("Open Serial"))
    {
        serial = new QSerialPort;
        //port
        serial->setPortName(ui->PortBox->currentText());
        //serial
        serial->open(QIODevice::ReadWrite);
        //baud rate
        serial->setBaudRate(ui->BaudBox->currentText().toInt());
        //data bits
        switch(ui->BitNumBox->currentIndex())
        {
        case 8: serial->setDataBits(QSerialPort::Data8); break;
        default: break;
        }
        //parity
        switch(ui->ParityBox->currentIndex())
        {
        case 0: serial->setParity(QSerialPort::NoParity); break;
        default: break;
        }
        //stop bit
        switch(ui->StopBox->currentIndex())
        {
        case 1: serial->setStopBits(QSerialPort::OneStop); break;
        case 2: serial->setStopBits(QSerialPort::TwoStop); break;
        default: break;
        }
        //flow control
        serial->setFlowControl(QSerialPort::NoFlowControl);

        //close enable
        ui->PortBox->setEnabled(false);
        ui->BaudBox->setEnabled(false);
        ui->BitNumBox->setEnabled(false);
        ui->ParityBox->setEnabled(false);
        ui->StopBox->setEnabled(false);
        ui->openButton->setText(tr("Close Serial"));
        ui->sendButton->setEnabled(true);

        //connect
        //read_data:signal ; slot:read_data;
        QObject::connect(serial, &QSerialPort::readyRead, this, &SocketTestQ::Read_Data);
        click_uid = false;
        click_anti = false;
        click_sqa = false;
    }
    else
    {
        //close serial
        serial->clear();
        serial->close();
        serial->deleteLater();

        //enable
        ui->PortBox->setEnabled(true);
        ui->BaudBox->setEnabled(true);
        ui->BitNumBox->setEnabled(true);
        ui->ParityBox->setEnabled(true);
        ui->StopBox->setEnabled(true);
        ui->openButton->setText(tr("Open Serial"));
        ui->sendButton->setEnabled( false);
    }
}
//find the card
void SocketTestQ::on_pushButton_clicked()
{
    click_uid = true;
    QByteArray array_sel_uid{sel_uid,sizeof(sel_uid)};
    qDebug() << array_sel_uid;
    if(ui->openButton->text()==tr("Close Serial"))
    {
  //      QString str_input = "&?;";
        serial->write(array_sel_uid);
    }
    else
    {
      QMessageBox::information(this,"warning","please open the serial");
    }
}

//select card anti 9320
void SocketTestQ::on_pushButton_2_clicked()
{
    click_anti = true;
    QByteArray array_sel_anti{sel_anti,sizeof(sel_anti)};
    if(ui->openButton->text()==tr("Close Serial"))
    {
 //       QString str_input = "T]?;";
        serial->write(array_sel_anti);
    }
    else
    {
        QMessageBox::information(this,"warning","please open the serial");
    }
}

//SQA
void SocketTestQ::on_pushButton_3_clicked()
{
    click_sqa = true;
    QByteArray array_sel_sqa{sel_sqa,sizeof(sel_sqa)};
    if(ui->openButton->text()==tr("Close Serial"))
    {
        serial->write(array_sel_sqa);
    }
    else
    {
        QMessageBox::information(this,"warning","please open the serial");
    }
}
//hexstr -> str(10)
QByteArray SocketTestQ::getByteArray(QString str)
{
    QByteArray packet;
    bool bNonHexSymbol = false;
//    QString strTmp = ui->uiUdpMsg->text().toUpper();
    QString strTmp = str;
    for(int c = 0; c < strTmp.toUtf8().length(); c++)
    {
        if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
        {
            packet.append( (strTmp.toUtf8().at(c) - 48) );
            qDebug() << (strTmp.toUtf8().at(c) - 48);
        }
        else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
        {
            packet.append( (strTmp.toUtf8().at(c) - 55) );
            qDebug() << (strTmp.toUtf8().at(c) - 55);
        }
        else
            bNonHexSymbol = true;
      }
    return packet;
}
//ASCLL -> hexstr
QString SocketTestQ::byteArrayToHexString(QString str)
{
    QString temp ="";
    QString single = "";
    bool ok;
    /*
    for(int i = 0;i < str.length();i++)
    {
        single = str[i] - '0' + 48;
        qDebug() << "single is " << single.toInt(&ok,16);
        temp += QString::number(single.toInt(&ok,16),16);
    }*/
    temp = str.toInt(&ok,16);
    qDebug() << temp;
    return temp;
}
//hexstr -> ascllstr
QString SocketTestQ::hexToAscall(QString in)
{
    std::string c_str = in.toStdString();
    std::string result = "";
    std::string temp3 = "";
    int first;
    int second;
    for(int i = 0; i < c_str.length(); i += 2)
    {
        if(c_str[i] - '0' > 10) first = 10 + c_str[i] - 'a';
        else first = c_str[i] - '0';
        if(c_str[i + 1] - '0' > 10) second = 10 + c_str[i + 1] - 'a';
        else second = c_str[i + 1] - '0';
            temp3 = first * 16 + second * 1;
        result += temp3;
    }
    qDebug()<<"result is:" <<  QString::fromStdString(result);
    return QString::fromStdString(result);
}
QByteArray SocketTestQ::hexStringToByte(QString hex)
{
   // QByteArray result;
    int len = (hex.length() / 2);
    int first,second;
    QByteArray result;
    result.resize(len);
    //std::char[] achar = hex.toCharArray();
    std::string temp = hex.toStdString();
    for (int i = 0; i < len; i++) {
        int pos = i * 2;
        if(temp[pos] - 'a' >= 0) first = 10 + temp[pos] - 'a';
        else if(temp[pos] - 'a' >= 0) first = 10 + temp[pos] - 'A';
        else first = temp[pos] - '0';
        if(temp[pos + 1] - 'a' >= 0) second = 10 + temp[pos + 1] - 'a';
        else if(temp[pos + 1] - 'a' >= 0) second = 10 + temp[pos + 1] - 'A';
        else second = temp[pos + 1] - '0';
        result[i] = (byte) ((first) << 4 | byte(second));
    }
    return result;
}

