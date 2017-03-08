#ifndef TCPPORTLIST_H
#define TCPPORTLIST_H

#include <QWidget>

namespace Ui {
class TCPPortList;
}

class TCPPortList : public QWidget
{
    Q_OBJECT

public:
    explicit TCPPortList(QWidget *parent = 0);
    ~TCPPortList();

private:
    Ui::TCPPortList *ui;
};

#endif // TCPPORTLIST_H
