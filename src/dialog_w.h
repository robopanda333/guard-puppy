#pragma once

#include <string>

#include <QDialog>
#include <QFileDialog>
#include <QCheckBox>
#include <QErrorMessage>
#include <boost/foreach.hpp>

#include "ui_guardPuppy.h"
#include "firewall.h"
#include "zone.h"
#include "userDefinedProtocolTreeHelpers.h"

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
    QStandardItemModel * t;
    public:
        AddUDPToTable_( QStandardItemModel * t_):t(t_)
        {}
        void operator()(ProtocolEntry const & pe)
        {
            if(pe.getClassification() == "User Defined")
            {
                //create an empty item
                QStandardItem* parent = new QStandardItem;
                std::string s = pe.getName();
                parent->setText(s.c_str());//set the name for the parent
                parent->setData(s.c_str(), Qt::EditRole); //"previous" name
                //next get the list of types and range strings
                std::vector<uchar> types = pe.getTypes();
                std::vector<std::string> rngs = pe.getRangeStrings();
                std::vector<bool> bid = pe.getBidirectionals();
                for(uint i(0); i < rngs.size(); i++)
                {
                    QList<QStandardItem *> child;
                    QStandardItem * temp;
                    temp = new QStandardItem(s.c_str());//name
                    child.push_back(temp);
                    temp = new QStandardItem();
                    temp->setData(types[i], Qt::EditRole);//type
                    temp->setData(((types[i]==IPPROTO_TCP)? "TCP" : "UDP"), Qt::DisplayRole);
                    child.push_back(temp);
                    temp = new QStandardItem(rngs[i].c_str());
                    child.push_back(temp);
                    temp = new QStandardItem("");
                    if(types[i]==IPPROTO_TCP)
                        temp->setFlags(0);
                    temp->setData(bid[i]?"Bidirectional":"Unidirectional", Qt::EditRole);
                    //temp->setCheckable(true);
                    child.push_back(temp);
                    parent->appendRow(child);
                }
                t->appendRow(parent);
            }
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
        QStandardItemModel * model = new QStandardItemModel(0,4, userDefinedProtocolTreeView);
        userDefinedProtocolTreeView->setModel(model);
        UDPTreeDelegate* tempDelegate = new UDPTreeDelegate(&firewall, this);
        userDefinedProtocolTreeView->setItemDelegate(tempDelegate);
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
    void on_zoneFileImportPushButton_clicked();

    void on_newUserDefinedProtocolPushButton_clicked();
    void on_deleteUserDefinedProtocolPushButton_clicked();
    void on_NewPortRangePushButton_clicked();
    void on_deletePortRangePushButton_clicked();

/*
    void on_userDefinedProtocolTreeView_dataChanged(QModelIndex const & current, QModelIndex const &);
*/

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

    //void on_userDefinedProtocolBidirectionalCheckBox_stateChanged( int state );//

    //  The spinboxes
    void on_logRateSpinBox_valueChanged( int value );
    void on_logBurstSpinBox_valueChanged( int value );
    void on_logWarnRateLimitSpinBox_valueChanged( int value );
    void on_localPortRangeLowSpinBox_valueChanged( int value );
    void on_localPortRangeHighSpinBox_valueChanged( int value );
    void on_logLevelComboBox_currentIndexChanged(int value);
/*
    void on_userDefinedProtocolTypeComboBox_currentIndexChanged(int value);     //
    void on_userDefinedProtocolNameLineEdit_textEdited(QString const & text);  //
    void on_userDefinedProtocolPortStartSpinBox_editingFinished( );      //
    void on_userDefinedProtocolPortEndSpinBox_editingFinished( );        //
*/

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
    
    void CurrentlySelectedUDPIndexes( int& i, int& j)
    {
        QModelIndex cur = userDefinedProtocolTreeView->currentIndex();
        j = i = -1;
        if(cur.isValid())
        {
            QModelIndex parent = cur.parent();
            if(parent.isValid())
            {
                i = parent.row();
                j = cur.row();
            }
            else
            {
                i = cur.row();
            }
        }
    }
};


