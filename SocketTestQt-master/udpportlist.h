#ifndef UDPPORTLIST_H
#define UDPPORTLIST_H

#include <QWidget>

namespace Ui {
class UDPPortList;
}

class UDPPortList : public QWidget
{
    Q_OBJECT

public:
    explicit UDPPortList(QWidget *parent = 0);
    ~UDPPortList();

private:
    Ui::UDPPortList *ui;
};

#endif // UDPPORTLIST_H
