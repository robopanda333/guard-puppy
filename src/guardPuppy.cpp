
#include <QApplication>
#include <QMessageBox>
#include "unistd.h"
#include "dialog_w.h"
#include "protocoldb.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    bool superUser = getuid() == 0;
    //this only checks to see if the user is root. but there may be other groups or users who have superuser privlages.
    //a better method of checking if the user can perform the needed tasks is required.
    //in fact i don't think there should be any check at all.
    ProtocolDB pdb("protocoldb/networkprotocoldb.xml");

    GuardPuppyFireWall firewall( superUser , pdb);

    GuardPuppyDialog_w guardPuppyDialog( firewall, pdb);

    if ( !superUser )
    {
        QMessageBox::information(0, QString::null, QString("WARNING"), QObject::tr(
                "Since you do not have superuser privileges, Guarddog is running with\n"
                "reduced functionality. Firewall scripts may be Imported/Exported, but\n"
                "the system's firewall settings may not be changed.\n"));
    }


    int rc = 0;
    try
    {
        guardPuppyDialog.show();
        rc = app.exec();
    }
    catch ( std::string const & msg )
    {
        std::cout << "Caught: " << msg << std::endl;
    }
    return rc;
}
