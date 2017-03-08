#include <QApplication>
#include "SocketTestQ.h"

int main(int argc, char* argv[])
{
    QApplication App(argc, argv);

    SocketTestQ ProgramWindow;
    ProgramWindow.show();

    return App.exec();
}
