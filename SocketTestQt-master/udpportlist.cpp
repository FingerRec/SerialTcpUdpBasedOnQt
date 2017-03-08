#include "udpportlist.h"
#include "ui_udpportlist.h"

UDPPortList::UDPPortList(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::UDPPortList)
{
    ui->setupUi(this);
    QStringList labels;
    labels << tr("Port No") << tr("Use") << tr("Description");
    ui->uiUDPPortList->setHorizontalHeaderLabels(labels);
}

UDPPortList::~UDPPortList()
{
    delete ui;
}
