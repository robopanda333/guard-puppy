#pragma once

#include <string>

#include <QDialog>
#include <QFileDialog>
#include <QCheckBox>
#include <QErrorMessage>

#include "ui_guardPuppy.h"

#include <boost/foreach.hpp>

#include "firewall.h"

#include "zone.h"

class ProtocolCheckBox : public QCheckBox
{
    Q_OBJECT;

    std::string zoneTo;
    std::string protocol;
public:
    ProtocolCheckBox( std::string const & _zoneTo, std::string const & _protocol, QWidget * parent )
     : QCheckBox( parent ), zoneTo( _zoneTo ), protocol( _protocol )
    {
    }
signals:
    void protocolStateChanged( std::string const & , std::string const & , Zone::ProtocolState );
public slots:
    void stateChanged(int);
};


class GuardPuppyDialog_w : public QDialog, Ui::GuardPuppyDialog
{
    Q_OBJECT;
    bool guiReady;
    GuardPuppyFireWall & firewall;
    ProtocolDB & pdb;

//private functors
    class AddProtocolToTable_
    {
    GuardPuppyDialog_w & g;
    std::vector<std::string> connectedZones;
    public:
        AddProtocolToTable_(GuardPuppyDialog_w & i, std::vector<std::string> s):g(i), connectedZones(s)
        {}
        void operator()(ProtocolEntry const & pe);
    };
    class AddUDPToTable_
    {
    QTreeWidget * t;
    public:
        AddUDPToTable_( QTreeWidget * t_):t(t_)
        {}
        void operator()(ProtocolEntry const & pe)
        {
            if(pe.Classification == "User Defined")
            {
                //create an empty item
                QTreeWidgetItem* parent = new QTreeWidgetItem(t, 0);
                std::string s = pe.getName();
                parent->setText(0, s.c_str());//set the name for the parent
                //next get the list of types and range strings
                std::vector<uchar> types = pe.getTypes();
                std::vector<std::string> rngs = pe.getRangeStrings();
                for(uint i(0); i < rngs.size(); i++)
                {
                    QTreeWidgetItem * child = new QTreeWidgetItem(parent);
                    child->setText(0, s.c_str() );
                    child->setText(1, types[i]==IPPROTO_TCP ? QObject::tr("TCP") : QObject::tr("UDP") );
                    child->setText(2, rngs[i].c_str() );
                }
            }
        }
    };
    class numberOfUDP_
    {
        int count;
    public:
        numberOfUDP_():count(0)
        {}
        int value(){return count;}
        void reset() {count = 0;}
        void operator()(ProtocolEntry const & pe)
        {
            if(pe.Classification == "User Defined")
            {
                count++;
            }
        }
    };
    class changeProtocolType_
    {
        uchar s;
        int j;
    public:
        changeProtocolType_(uchar s_, int j_):s(s_), j(j_)
        {}
        void operator()(ProtocolEntry & pe)
        {
            pe.setType(s, j);
        }
    };
    class changeProtocolName_
    {
        std::string s;
    public:
        changeProtocolName_(std::string s_):s(s_)
        {}
        void operator()(ProtocolEntry & pe)
        {
            pe.name = s;
            pe.longname = s;
        }
    };
    class changeProtocolBi_
    {
        bool s;
        int j;
    public:
        changeProtocolBi_(bool s_, int j_):s(s_), j(j_)
        {}
        void operator()(ProtocolEntry & pe)
        {
            pe.setBidirectional(s, j);
        }
    };
    class changeProtocolPort_
    {
        int s;
        int j;
        QTreeWidgetItem * t;
        bool start;
        bool changeother;
    public:
        changeProtocolPort_(int s_, int j_, QTreeWidgetItem * t_, bool start_ = true):s(s_), j(j_), t(t_),start(start_), changeother(false)
        {}
        bool pChange(){return changeother;}
        void operator()(ProtocolEntry & pe)
        {
            if(start)
            {
                pe.setStartPort(s, j);
            }
            else
            {
                pe.setEndPort(s, j);
            }
            changeother = pe.getEndPorts()[j] == pe.getStartPorts()[j];
            t->child(j)->setText(2,pe.getRangeStrings()[j].c_str());
        }
    };
    class addNewRange_
    {
    public:
        void operator()(ProtocolEntry & pe)
        {
            ProtocolNetUse t;
            t.addDest(ProtocolNetUseDetail());
            pe.addNetwork(t);
        }
    };
    class deleteRange_
    {
        uint i;
    public:
        deleteRange_(uint i_):i(i_)
        { }
        void operator()(ProtocolEntry & pe)
        {
            pe.deleteNetwork(i);
        }
    };

public:
    GuardPuppyDialog_w( GuardPuppyFireWall & _firewall, ProtocolDB & _pdb)
        : guiReady( false ), firewall( _firewall), pdb( _pdb )
    {
        //! \todo Read program options, i.e window geometery
        setupUi( this );
        if ( firewall.isSuperUserMode() == false )
        {
            //it may be better to have this check in the buttons and
            //tell the user that changes did infact succeed or not.

            okayPushButton->setEnabled( false );
            applyPushButton->setEnabled( false );
        }
        guiReady = true;
        rebuildGui();
    }

    void rebuildGui();
    void setZoneGUI( ::Zone const & zone);
    void setZoneAddressGUI( ::Zone const & zone);
    void setZonePageEnabled( ::Zone const & thisZone, bool enabled);
    void setZoneConnectionGUI( ::Zone const & zone);
    void setUserDefinedProtocolGUI( std::string const &, int const j) ;
    void buildConnectionGUI() ;
    void createProtocolPages();
    void setProtocolPagesEnabled(bool enabled);
    void setAdvancedPageEnabled(bool enabled);
    void setLoggingPageEnabled(bool enabled);
    void createUdpTableWidget();


private slots:
    void on_aboutPushButton_clicked();
    void on_okayPushButton_clicked();
    void on_cancelPushButton_clicked();
    void on_applyPushButton_clicked();

    void on_protocolZoneListWidget_currentItemChanged( QListWidgetItem * current, QListWidgetItem * previous );
    void on_zoneListWidget_currentItemChanged( QListWidgetItem * current, QListWidgetItem * previous );
    void on_zoneNameLineEdit_textChanged( QString const & text );
    void on_zoneAddressListBox_currentItemChanged( QListWidgetItem * current, QListWidgetItem * previous );
    void on_zoneAddressLineEdit_textChanged( QString const & text );
    void on_newZoneAddressPushButton_clicked();
    void on_deleteZoneAddressPushButton_clicked();
    void on_newZonePushButton_clicked();
    void on_deleteZonePushButton_clicked();
    void on_tabWidget_currentChanged( int index );
    void on_protocolTreeWidget_itemClicked( QTreeWidgetItem * item, int column );
    void on_protocolTreeWidget_itemChanged( QTreeWidgetItem * item, int column );
    void protocolStateChanged( std::string const & zoneTo, std::string const & protocol, Zone::ProtocolState state );
    void on_zoneConnectionTableWidget_itemChanged( QTableWidgetItem * item );
    void on_zoneCommentLineEdit_editingFinished();

    void on_advImportPushButton_clicked();
    void on_advExportPushButton_clicked();
    void on_advRestoreFactoryDefaultsPushButton_clicked();

    void on_newUserDefinedProtocolPushButton_clicked();
    void on_deleteUserDefinedProtocolPushButton_clicked();
    void on_NewPortRangePushButton_clicked();
    void on_deletePortRangePushButton_clicked();

    void on_userDefinedProtocolTreeWidget_currentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem*);
    //  All the checkbox options
    void on_logDroppedPacketsCheckBox_stateChanged( int state );
    void on_logRejectPacketsCheckBox_stateChanged( int state );
    void on_logAbortedTcpCheckBox_stateChanged( int state );
    void on_logUserRateLimitCheckBox_stateChanged( int state );
    void on_logWarnRateLimitCheckBox_stateChanged( int state );
    void on_logIpOptionsCheckBox_stateChanged( int state );
    void on_logTcpSequenceCheckBox_stateChanged( int state );
    void on_logTcpOptionsCheckBox_stateChanged( int state );

    void on_disableFirewallCheckBox_stateChanged( int state );
    void on_allowTcpTimeStampsCheckBox_stateChanged( int state );
    void on_enableDhcpCheckBox_stateChanged( int state );
    void on_enableDhcpdCheckBox_stateChanged( int state );

    void on_userDefinedProtocolBidirectionalCheckBox_stateChanged( int state );//

    //  The spinboxes
    void on_logRateSpinBox_valueChanged( int value );
    void on_logBurstSpinBox_valueChanged( int value );
    void on_logWarnRateLimitSpinBox_valueChanged( int value );
    void on_localPortRangeLowSpinBox_valueChanged( int value );
    void on_localPortRangeHighSpinBox_valueChanged( int value );
    void on_logLevelComboBox_currentIndexChanged(int value);

    void on_userDefinedProtocolTypeComboBox_currentIndexChanged(int value);     //
    void on_userDefinedProtocolNameLineEdit_textEdited(QString const & text);  //
    void on_userDefinedProtocolPortStartSpinBox_editingFinished( );      //
    void on_userDefinedProtocolPortEndSpinBox_editingFinished( );        //


private:
    std::string currentZoneName() const
    {
        if ( zoneListWidget->currentItem() )
            return zoneListWidget->currentItem()->text().toStdString();
        return "";
    }
    std::string currentProtocolZoneName() const
    {
        if ( protocolZoneListWidget->currentItem() )
            return protocolZoneListWidget->currentItem()->text().toStdString();
        return "";
    }
    std::string currentMachineName() const
    {
        if ( zoneAddressListBox->currentItem() )
            return zoneAddressListBox->currentItem()->text().toStdString();
        return "";
    }
    void CurrentlySelectedUDPIndexes(int& i, int& j)
    {
        QTreeWidgetItem * cur,* parent,* child;
        parent = child = 0;
        j = i = 0;
        cur = userDefinedProtocolTreeWidget->currentItem();
        
        if(cur)
        {
            if(!cur->childCount())//if we have no children we are at the detail level
            {
                parent = cur->parent();
                child = cur;
            }
            else//if we do then we are at a toplevel, take the first child
                parent = cur;
            if(child)
                j = parent->indexOfChild(child);

            i = userDefinedProtocolTreeWidget->indexOfTopLevelItem(parent);
        }
        else//there isn't a current item. error out
            i = j = -1;

    }


};


