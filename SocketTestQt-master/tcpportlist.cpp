#include "tcpportlist.h"
#include "ui_tcpportlist.h"

TCPPortList::TCPPortList(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TCPPortList)
{
    ui->setupUi(this);
    QStringList labels;
    labels << tr("Port No") << tr("Use") << tr("Description");
    ui->uiTCPPortList->setHorizontalHeaderLabels(labels);
}

TCPPortList::~TCPPortList()
{
    delete ui;
}
