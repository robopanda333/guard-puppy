#include "dialog_w.h"
#include "aboutDialog_w.h"

unsigned int Zone::nextId = 0;

void GuardPuppyDialog_w::on_tabWidget_currentChanged( int /* index */ )
{
    rebuildGui();
}

void GuardPuppyDialog_w::on_aboutPushButton_clicked()
{
    GuardPuppyAboutDialog_w aboutDialog;
    aboutDialog.exec();
}

void GuardPuppyDialog_w::on_protocolTreeWidget_itemClicked( QTreeWidgetItem * item, int column )
{
    //! \todo Add discriptions to the protocol buckets, or handle in this function not updating when they are clicked
    std::string protocol = item->text( column ).toStdString();
    //fills in the Protocol discription based on the curently selected Protocol
    protocolTextEdit->setText( firewall.getProtocolText( protocol ).c_str() );
}

void GuardPuppyDialog_w::on_protocolTreeWidget_itemChanged( QTreeWidgetItem * item, int column )
{
    std::string protocol = item->text( column ).toStdString();
}


///////////////////////////////////////////////////////////////////////////
void GuardPuppyDialog_w::on_okayPushButton_clicked()
{
    firewall.saveAndApply();
    //! \todo also save program state, i.e. what the current window size, position is, saveOptions()
    close();
}

void GuardPuppyDialog_w::on_cancelPushButton_clicked()
{
    close();
}

void GuardPuppyDialog_w::on_applyPushButton_clicked()
{
    firewall.apply();
}

void GuardPuppyDialog_w::on_protocolZoneListWidget_currentItemChanged( QListWidgetItem * /* current */, QListWidgetItem * /* previous  */)
{
    std::string str = "Protocols served FROM zone '";
    str += currentProtocolZoneName();
    str += "' TO clients in zones: ";

    protocolZoneLabel->setText( str.c_str() );
    createProtocolPages();
}

void GuardPuppyDialog_w::on_zoneListWidget_currentItemChanged( QListWidgetItem * /* current */, QListWidgetItem * /* previous */ )
{
    if ( currentZoneName() != "" )
    {
        setZoneGUI( firewall.getZone( currentZoneName() ) );
        setZoneAddressGUI( firewall.getZone( currentZoneName() ) );
        setZoneConnectionGUI( firewall.getZone( currentZoneName() ) );
    }
}

void GuardPuppyDialog_w::on_zoneNameLineEdit_textChanged( QString const & text )
{
    std::string s = text.toStdString();
    std::replace(s.begin(), s.end(), ' ', '_');
    firewall.zoneRename( currentZoneName(), s );

    if ( zoneListWidget->currentItem() )
    {
        zoneListWidget->currentItem()->setText( s.c_str() );
//        protocolZoneListWidget->currentItem()->setText( text );
    }

    if ( currentZoneName() != "" )
    {
        setZoneGUI( firewall.getZone( currentZoneName() ) );
        setZoneAddressGUI( firewall.getZone( currentZoneName() ) );
        setZoneConnectionGUI( firewall.getZone( currentZoneName() ) );
    }

}

void GuardPuppyDialog_w::on_zoneAddressListBox_currentItemChanged( QListWidgetItem * current, QListWidgetItem * /* previous */ )
{
    if ( current )
    {
        zoneAddressLineEdit->setText( current->text() );

        if ( firewall.getZone( currentZoneName() ).editable() )
            zoneAddressLineEdit->setEnabled( true );
        else
            zoneAddressLineEdit->setEnabled( false );
    }
}

void GuardPuppyDialog_w::on_zoneAddressLineEdit_textChanged( QString const & text )
{
    firewall.setNewMachineName( currentZoneName(), currentMachineName(), text.toStdString() );

    if ( zoneAddressListBox->currentItem() )
        zoneAddressListBox->currentItem()->setText( text );
}

void GuardPuppyDialog_w::on_newZonePushButton_clicked()
{
    firewall.addZone( "new zone" );
    zoneListWidget->addItem( "new zone" );
//    protocolZoneListWidget->addItem( "new zone" );
    zoneListWidget->setCurrentRow( zoneListWidget->count() - 1 );
//    protocolZoneListWidget->setCurrentRow( protocolZoneListWidget->count() - 1 );
}

void GuardPuppyDialog_w::on_deleteZonePushButton_clicked()
{
    firewall.deleteZone( currentZoneName() );
    QListWidgetItem * item = zoneListWidget->takeItem( zoneListWidget->currentRow() );
    if ( item )
    {
        delete item;
    }
}


void GuardPuppyDialog_w::on_newZoneAddressPushButton_clicked()
{
    firewall.addNewMachine( currentZoneName(), "addr" );

    zoneAddressListBox->addItem( "addr" );
    zoneAddressListBox->setCurrentRow( zoneAddressListBox->count() - 1 );
}

void GuardPuppyDialog_w::on_deleteZoneAddressPushButton_clicked()
{
    firewall.deleteMachine( currentZoneName(), currentMachineName() );

    QListWidgetItem * item = zoneAddressListBox->takeItem( zoneAddressListBox->currentRow() );
    if ( item )
    {
        delete item;
    }
}


void GuardPuppyDialog_w::rebuildGui()
{
    if ( guiReady )
    {
        checkBox_3->setCheckState( Qt::PartiallyChecked );

        zoneListWidget->clear();
        protocolZoneListWidget->clear();
        std::vector< std::string > zones = firewall.getZoneList();
        BOOST_FOREACH( std::string const & s, zones )
        {
            zoneListWidget->addItem( QString( s.c_str() ) );
            protocolZoneListWidget->addItem( QString( s.c_str() ) );
        }
        zoneListWidget->setCurrentRow( 0 );
        protocolZoneListWidget->setCurrentRow( 0 );

        buildConnectionGUI();

        if ( firewall.zoneCount() > 0 && currentZoneName() != "" )
        {
            setZoneGUI( firewall.getZone( currentZoneName() ) );
            setZoneAddressGUI( firewall.getZone( currentZoneName() ) );
            setZoneConnectionGUI( firewall.getZone( currentZoneName() ) );
        }
//        setUserDefinedProtocolGUI( UserDefinedProtocol const & userprotocol)

        // Put the widgets in the right state for the logging page.
        logDroppedPacketsCheckBox->setChecked(firewall.isLogDrop());
        logRejectPacketsCheckBox->setChecked(firewall.isLogReject());
        logAbortedTcpCheckBox->setChecked(firewall.isLogAbortedTCP());
        logIpOptionsCheckBox->setChecked(firewall.isLogIPOptions());
        logTcpSequenceCheckBox->setChecked(firewall.isLogTCPSequence());
        logTcpOptionsCheckBox->setChecked(firewall.isLogTCPOptions());
        logLevelComboBox->setCurrentIndex(firewall.getLogLevel());
        logUserRateLimitCheckBox->setChecked(firewall.isLogRateLimit());

        logRateSpinBox->setValue(firewall.getLogRate());

        logRateUnitComboBox->setCurrentIndex(firewall.getLogRateUnit());
        logBurstSpinBox->setValue(firewall.getLogRateBurst());
        logWarnRateLimitCheckBox->setChecked(firewall.isLogWarnLimit());
        logWarnRateLimitSpinBox->setValue(firewall.getLogWarnLimitRate());
        logWarnRateUnitComboBox->setCurrentIndex(firewall.getLogWarnLimitRateUnit());

        // Put the widgets in the right state for the Advanced page.
        uint start, end;
        firewall.getLocalDynamicPortRange(start,end);
        localPortRangeLowSpinBox->setValue(start);
        localPortRangeHighSpinBox->setValue(end);

        disableFirewallCheckBox->setChecked(firewall.isDisabled());

        enableDhcpCheckBox->setChecked(firewall.isDHCPcEnabled());
        dhcpInterfaceNameLineEdit->setText(firewall.getDHCPcInterfaceName().c_str());

        enableDhcpdCheckBox->setChecked(firewall.isDHCPdEnabled());
        dhcpdInterfaceNameLineEdit->setText(firewall.getDHCPdInterfaceName().c_str());

        allowTcpTimeStampsCheckBox->setChecked(firewall.isAllowTCPTimestamps());

        createUdpTableWidget();
        createProtocolPages();
        setProtocolPagesEnabled(!firewall.isDisabled());
        setAdvancedPageEnabled(!firewall.isDisabled());
        if ( firewall.zoneCount() > 0 && currentZoneName() != "" )
            setZonePageEnabled(firewall.getZone( currentZoneName() ), !firewall.isDisabled());
        setLoggingPageEnabled(!firewall.isDisabled());

        descriptionEdit->setText(firewall.description.c_str());
    }
}
void GuardPuppyDialog_w::setLoggingPageEnabled(bool enabled)
{

    bool logging = firewall.isLogReject() || firewall.isLogDrop();
        // Logging and options.
    logDroppedPacketsCheckBox->setEnabled(enabled);
    logRejectPacketsCheckBox->setEnabled(enabled);
    logIpOptionsCheckBox->setEnabled(enabled && logging);
    logTcpSequenceCheckBox->setEnabled(enabled && logging);
    logTcpOptionsCheckBox->setEnabled(enabled && logging);
    logLevelComboBox->setEnabled(enabled && logging);
    logAbortedTcpCheckBox->setEnabled(enabled && logging);

        // Rate limiting.
    logUserRateLimitCheckBox->setEnabled(enabled && logging);
    bool limiting = logging && firewall.isLogRateLimit();
    logRateSpinBox->setEnabled(enabled && limiting);
    logRateUnitComboBox->setEnabled(enabled && limiting);
    logBurstSpinBox->setEnabled(enabled && limiting);
        // Limit warning.
    logWarnRateLimitCheckBox->setEnabled(enabled && limiting);
    logWarnRateLimitSpinBox->setEnabled(enabled && limiting && firewall.isLogWarnLimit());
    logWarnRateUnitComboBox->setEnabled(enabled && limiting && firewall.isLogWarnLimit());
}


///////////////////////////////////////////////////////////////////////////
void GuardPuppyDialog_w::setProtocolPagesEnabled(bool enabled)
{
    protocolZoneListWidget->setEnabled( enabled );
    protocolTextEdit->setEnabled( enabled );
    protocolTreeWidget->setEnabled( enabled );
}

//Qt::CheckState itemState = qobject_cast<QCheckBox*>(treeWidget->itemWidget(item, 0))->checkState();

void ProtocolCheckBox::stateChanged( int state )
{
    std::map< int, Zone::ProtocolState> buttonToProtocolStates;
    buttonToProtocolStates[ Qt::Unchecked ]        = Zone::DENY;
    buttonToProtocolStates[ Qt::PartiallyChecked ] = Zone::REJECT;
    buttonToProtocolStates[ Qt::Checked ]          = Zone::PERMIT;
    emit protocolStateChanged( zoneTo, protocol, buttonToProtocolStates[ state ] );
}

void GuardPuppyDialog_w::protocolStateChanged( std::string const & zoneTo, std::string const & protocol, Zone::ProtocolState state )
{
    firewall.setProtocolState( currentProtocolZoneName(), zoneTo, protocol, state );
}

void GuardPuppyDialog_w::createProtocolPages()
{
    protocolTreeWidget->clear();

    //protocolTreeWidget->setColumnCount( 1 );

    std::vector< std::string > connectedZones = firewall.getConnectedZones( currentProtocolZoneName() );
    QStringList columns;
    columns += "Network Protocol";
    BOOST_FOREACH( std::string const & col, connectedZones )
    {
        columns += col.c_str();
    }

    protocolTreeWidget->setHeaderLabels( columns );
    
    AddProtocolToTable_ aptt(*this, connectedZones);
    firewall.ApplyToDB(aptt);

}

void GuardPuppyDialog_w::AddProtocolToTable_::operator()(ProtocolEntry const & pe)
{
    int index(0);
    QTreeWidgetItem * parent = 0;
    for(; index < g.protocolTreeWidget->topLevelItemCount() && !parent; index++)
    {
        if(pe.Classification == g.protocolTreeWidget->topLevelItem(index)->text(0).toStdString())
            parent = g.protocolTreeWidget->topLevelItem(index);
    }
    if(!parent)
    {//add new top level parent of the same class.
        parent = new QTreeWidgetItem( QStringList( pe.Classification.c_str() ) );
        g.protocolTreeWidget->addTopLevelItem( parent );
    }
    QTreeWidgetItem * item = new QTreeWidgetItem(parent, QStringList( pe.longname.c_str() ) );

    g.protocolTreeWidget->header()->setResizeMode( QHeaderView::ResizeToContents );
    
    //QTreeWidgetItem *item = new QTreeWidgetItem( categoryList[pe.classification], QStringList( pe.longname.c_str() ) );
    item->setFlags( item->flags() | Qt::ItemIsUserCheckable );

    for ( size_t i = 0; i < connectedZones.size(); i++ )
    {
        ProtocolCheckBox * itemCheckBox = new ProtocolCheckBox(connectedZones[i], pe.name, g.protocolTreeWidget);
        itemCheckBox->setTristate();
        Zone::ProtocolState ps = g.firewall.getProtocolState( g.currentProtocolZoneName(), connectedZones[i], pe.name );
        if ( ps == Zone::DENY )
            itemCheckBox->setCheckState( Qt::Unchecked );
        else if ( ps == Zone::REJECT )
            itemCheckBox->setCheckState( Qt::PartiallyChecked );
        else
            itemCheckBox->setCheckState( Qt::Checked );

        g.protocolTreeWidget->setItemWidget(item, i+1, itemCheckBox);
        connect( itemCheckBox, SIGNAL( stateChanged(int) ), itemCheckBox, SLOT( stateChanged(int)) );
        connect( itemCheckBox, SIGNAL( protocolStateChanged(std::string const&, std::string const &, Zone::ProtocolState) ), &g, SLOT( protocolStateChanged(std::string const &, std::string const &, Zone::ProtocolState)) );
    }
}


void GuardPuppyDialog_w::setZoneGUI( ::Zone const & zone )
{
    zoneNameLineEdit->setText( zone.getName().c_str());
    zoneCommentLineEdit->setText( zone.getComment().c_str());

    if ( zone.editable() )
    {
        zoneNameLineEdit->setReadOnly(false);
        zoneCommentLineEdit->setReadOnly(false);
        deleteZonePushButton->setEnabled(true);
    }
    else
    {
        zoneNameLineEdit->setReadOnly(true);
        zoneCommentLineEdit->setReadOnly(true);
        deleteZonePushButton->setEnabled(false);
    }
}

void GuardPuppyDialog_w::setZoneAddressGUI( ::Zone const & zone)
{
        // Clean out the address list box.
    zoneAddressListBox->clear();

    zoneAddressListBox->setEnabled( zone.editable());

    BOOST_FOREACH( IPRange const & it, zone.getMemberMachineList() )
    {
        zoneAddressListBox->addItem(it.getAddress().c_str());
    }
        // Display a special message for the Local zone.
    if(zone.isLocal())
    {
        zoneAddressListBox->addItem(QObject::tr("<< IP addresses on the local machine >>"));
    }
    // Display a special message for the Internet zone.
    if(zone.isInternet())
    {
        zoneAddressListBox->addItem(QObject::tr("<< IP addresses not matching any zone >>"));
    }

    newZoneAddressPushButton->setEnabled(zone.editable());

    if(!zone.getMemberMachineList().empty() )
    {
//        zoneAddressLineEdit->setText((zone.membermachine.at(0)).getAddress().c_str());
        zoneAddressListBox->setCurrentRow(0); //,true);
        zoneAddressListBox->setEnabled(true);
        deleteZoneAddressPushButton->setEnabled(true);
        zoneAddressLineEdit->setEnabled(true);
    }
    else
    {
        zoneAddressLineEdit->setText("");
        zoneAddressListBox->setEnabled(false);
        deleteZoneAddressPushButton->setEnabled(false);
        zoneAddressLineEdit->setEnabled(false);
    }
}

void GuardPuppyDialog_w::setZonePageEnabled(::Zone const & thisZone, bool enabled)
{
    if ( enabled)
    {
        newZoneAddressPushButton->setEnabled(true);
        zoneAddressListBox->setEnabled(true);

        newZoneAddressPushButton->setEnabled(thisZone.editable());
//        deleteZoneAddressPushButton->setEnabled(thisZone.editable());

        zoneNameLineEdit->setEnabled(true);
        zoneCommentLineEdit->setEnabled(true);

        if(!thisZone.getMemberMachineList().empty())
        {
            zoneAddressListBox->setEnabled(true);
//            deleteZoneAddressPushButton->setEnabled(true);
            zoneAddressLineEdit->setEnabled(true);
        }
        else
        {
            zoneAddressListBox->setEnabled(false);
//            deleteZoneAddressPushButton->setEnabled(false);
            zoneAddressLineEdit->setEnabled(false);
        }

    }
    else
    {
            // Disable the widgets.
        newZoneAddressPushButton->setEnabled(false);
        zoneAddressListBox->setEnabled(false);
        zoneNameLineEdit->setEnabled(false);
        zoneCommentLineEdit->setEnabled(false);
//        deleteZoneAddressPushButton->setEnabled(false);

        newZoneAddressPushButton->setEnabled(false);
//        deleteZoneAddressPushButton->setEnabled(false);
        zoneAddressLineEdit->setEnabled(false);
        zoneAddressListBox->setEnabled(false);
    }
}

void GuardPuppyDialog_w::on_zoneConnectionTableWidget_itemChanged( QTableWidgetItem * item )
{
    std::string fromZone = item->text().toStdString();
    firewall.updateZoneConnection( currentZoneName(), fromZone, item->checkState() == Qt::Checked);
}

void GuardPuppyDialog_w::on_zoneCommentLineEdit_editingFinished()
{
    firewall.getZone(currentZoneName()).setComment(zoneCommentLineEdit->text().toStdString());
}

void GuardPuppyDialog_w::setZoneConnectionGUI(::Zone const & zone)
{
    zoneConnectionTableWidget->setRowCount( 0 );
//    zoneConnectionTableWidget->clearContents();

    std::vector< std::string > const & zoneList = firewall.getZoneList();
    std::string zoneFrom = zone.getName();

    BOOST_FOREACH( std::string const & zoneTo, zoneList )
    {
        zoneConnectionTableWidget->insertRow( zoneConnectionTableWidget->rowCount() );
        QTableWidgetItem * item = new QTableWidgetItem( zoneTo.c_str() );
        bool connected = firewall.areZonesConnected( zoneFrom, zoneTo );
        if ( connected )
            item->setCheckState( Qt::Checked );
        else
            item->setCheckState( Qt::Unchecked );
        if ( zoneTo == zoneFrom )
            item->setFlags( item->flags() & ~Qt::ItemIsEnabled );  // cannot make zone connections to yourself.
        // \!todo  This is the way guarddog works, I'm not sure we need to say this.  It should be possible to have a single zone...
        // \!todo  change out for zone.editable(), since we have it.
        if ( (zoneFrom == "Internet" || zoneFrom == "Local" ) && ( zoneTo == "Internet" || zoneTo == "Local" ) )
            item->setFlags( item->flags() & ~Qt::ItemIsEnabled );  // cannot change default zones

        zoneConnectionTableWidget->setItem( zoneConnectionTableWidget->rowCount()-1, 0, item );
    }
}

void GuardPuppyDialog_w::on_advImportPushButton_clicked()
{
//! \todo add logic to handle readFirewall failure
    firewall.factoryDefaults();
    std::string filename;
    try
    {
        filename = QFileDialog::getOpenFileName(this, tr("Export GuardPuppy Config"), "~/", tr("All Files (*)")).toStdString();
    }
    catch(...)
    {//it was a bad file
        return;
    }
    if(filename=="")
        return;
    try
    {
        firewall.readFirewall(filename);
    }
    catch(std::string s)
    {
        QMessageBox::warning(this, "Import Failed", s.c_str());
        return;
    }
    catch(...)
    {
        std::string s = "Error opening file, are you sure it was a Guardpuppy or GuardDog file?";
        QMessageBox::warning(this, "Import Failed", s.c_str());
        return;
    }
    rebuildGui();//TODO figure out a better way of redrawing...?
}
void GuardPuppyDialog_w::on_advExportPushButton_clicked()
{
    std::string filename = QFileDialog::getSaveFileName(this, tr("Import GuardPuppy Config"), "~/.firewall.sh", tr("All Files (*)")).toStdString();
    firewall.save(filename);
}
void GuardPuppyDialog_w::on_advRestoreFactoryDefaultsPushButton_clicked(){
    firewall.factoryDefaults();
    rebuildGui();
}
void GuardPuppyDialog_w::on_newUserDefinedProtocolPushButton_clicked()
{
    std::string name        =   "New Protocol";
    uchar  udpType          =   IPPROTO_TCP;
    uint   udpStartPort     =   0;
    uint   udpEndPort       =   0;
    bool   udpBidirectional =   false;
    firewall.newUserDefinedProtocol(name, udpType, udpStartPort, udpEndPort, udpBidirectional);
    rebuildGui();
    QTreeWidgetItem * p = userDefinedProtocolTreeWidget->topLevelItem(userDefinedProtocolTreeWidget->topLevelItemCount()-1);
    userDefinedProtocolTreeWidget->scrollToItem(p);
    userDefinedProtocolTreeWidget->expandItem(p);
    userDefinedProtocolTreeWidget->setCurrentItem(p);
}

void GuardPuppyDialog_w::on_deleteUserDefinedProtocolPushButton_clicked()
{
    QTreeWidgetItem * item = userDefinedProtocolTreeWidget->currentItem();
    if(item)
    {
        std::string s = item->text(0).toStdString();
        firewall.deleteUserDefinedProtocol(s);
        rebuildGui();
    }
}

void GuardPuppyDialog_w::on_NewPortRangePushButton_clicked()
{
    int i; int j;
    CurrentlySelectedUDPIndexes(i, j);
    if( i>=0 && j>=0 )
    {
        addNewRange_ anr;
        firewall.ApplyToNthInClass(anr, i, "User Defined");
        rebuildGui();
        QTreeWidgetItem * p = userDefinedProtocolTreeWidget->topLevelItem(i);
        userDefinedProtocolTreeWidget->scrollToItem(p);
        userDefinedProtocolTreeWidget->expandItem(p);
        userDefinedProtocolTreeWidget->setCurrentItem(p->child(p->childCount()-1));
    }
}
void GuardPuppyDialog_w::on_deletePortRangePushButton_clicked()
{
    int i; int j;
    CurrentlySelectedUDPIndexes(i, j);
    if( i>=0 && j>=0 )
    {
        QTreeWidgetItem * p = userDefinedProtocolTreeWidget->topLevelItem(i);
        if(p->childCount()>1)
        {
            deleteRange_ dr(j);
            firewall.ApplyToNthInClass(dr, i, "User Defined");
            rebuildGui();
            userDefinedProtocolTreeWidget->scrollToItem(p);
            userDefinedProtocolTreeWidget->expandItem(p);
            userDefinedProtocolTreeWidget->setCurrentItem(p->child(p->childCount()-1));
        }
    }
}

void GuardPuppyDialog_w::on_userDefinedProtocolTreeWidget_currentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem*)
{
    int i;
    int j;
    CurrentlySelectedUDPIndexes(i,j);
    if(current)
    {
        std::string s = current->text(0).toStdString();
        if(j>=0)
            setUserDefinedProtocolGUI(s, j);
    }
}

void GuardPuppyDialog_w::setUserDefinedProtocolGUI(std::string const & s, int j)
{
        userDefinedProtocolNameLineEdit->setText(s.c_str());
        userDefinedProtocolTypeComboBox->setCurrentIndex(firewall.getTypes(s)[j] == IPPROTO_TCP ? 0 : 1);
        userDefinedProtocolPortStartSpinBox->setValue(firewall.getStartPorts(s)[j]);
        userDefinedProtocolPortEndSpinBox->setValue(firewall.getEndPorts(s)[j]);
        userDefinedProtocolBidirectionalCheckBox->setEnabled(firewall.getTypes(s)[j]==IPPROTO_UDP);
        userDefinedProtocolBidirectionalCheckBox->setChecked(firewall.getBidirectionals(s)[j]);
}

void GuardPuppyDialog_w::createUdpTableWidget()
{
    userDefinedProtocolTreeWidget->clear();
    QStringList s("Protocol");
    s << "Type";
    s << "Range";
    userDefinedProtocolTreeWidget->setHeaderLabels(s);
    userDefinedProtocolTreeWidget->setHeaderHidden(false);
    AddUDPToTable_ audptt(userDefinedProtocolTreeWidget);
    firewall.ApplyToDB(audptt);
}

void GuardPuppyDialog_w::setAdvancedPageEnabled(bool enabled)
{
    localPortRangeLowSpinBox->setEnabled(enabled);
    localPortRangeHighSpinBox->setEnabled(enabled);

    //std::vector< UserDefinedProtocol > const & udp = firewall.getUserDefinedProtocols();
    numberOfUDP_ count;
    firewall.ApplyToDB(count);
    bool gotudps = count.value();///*firewall.numberOfUserDefinedProtocols() >*/ 1 ;
    userDefinedProtocolTreeWidget->setEnabled(enabled);
    userDefinedProtocolNameLineEdit->setEnabled(enabled && gotudps);
    newUserDefinedProtocolPushButton->setEnabled(enabled);
    deleteUserDefinedProtocolPushButton->setEnabled(enabled && gotudps);
    userDefinedProtocolTypeComboBox->setEnabled(enabled && gotudps);
    userDefinedProtocolPortStartSpinBox->setEnabled(enabled && gotudps);
    userDefinedProtocolPortEndSpinBox->setEnabled(enabled && gotudps);

    userDefinedProtocolBidirectionalCheckBox->setEnabled(false);

    enableDhcpCheckBox->setEnabled( enabled );
    dhcpInterfaceNameLineEdit->setEnabled( enabled && firewall.isDHCPcEnabled() );

    enableDhcpdCheckBox->setEnabled( enabled );
    dhcpdInterfaceNameLineEdit->setEnabled( enabled && firewall.isDHCPdEnabled() );

    allowTcpTimeStampsCheckBox->setEnabled(enabled);

}

void GuardPuppyDialog_w::buildConnectionGUI()
{
}

void GuardPuppyDialog_w::on_logDroppedPacketsCheckBox_stateChanged( int state )
{
    firewall.setLogDrop( state );
}
void GuardPuppyDialog_w::on_logRejectPacketsCheckBox_stateChanged( int state )
{
    firewall.setLogReject( state );
}
void GuardPuppyDialog_w::on_logAbortedTcpCheckBox_stateChanged( int state )
{
    firewall.setLogAbortedTCP( state );
}
void GuardPuppyDialog_w::on_logUserRateLimitCheckBox_stateChanged( int state )
{
    firewall.setLogRateLimit( state );
}
void GuardPuppyDialog_w::on_logWarnRateLimitCheckBox_stateChanged( int state )
{
    firewall.setLogWarnLimitRate( state );
}
void GuardPuppyDialog_w::on_logIpOptionsCheckBox_stateChanged( int state )
{
    firewall.setLogIPOptions( state );
}
void GuardPuppyDialog_w::on_logTcpSequenceCheckBox_stateChanged( int state )
{
    firewall.setLogTCPSequence( state );
}
void GuardPuppyDialog_w::on_logTcpOptionsCheckBox_stateChanged( int state )
{
    firewall.setLogTCPOptions( state );
}

void GuardPuppyDialog_w::on_disableFirewallCheckBox_stateChanged( int state )
{
    firewall.setDisabled( state );
    rebuildGui();
}
void GuardPuppyDialog_w::on_allowTcpTimeStampsCheckBox_stateChanged( int state )
{
    firewall.setAllowTCPTimestamps( state );
}
void GuardPuppyDialog_w::on_enableDhcpCheckBox_stateChanged( int state )
{
    firewall.setDHCPcEnabled( state );
}
void GuardPuppyDialog_w::on_enableDhcpdCheckBox_stateChanged( int state )
{
    firewall.setDHCPdEnabled( state );
}

void GuardPuppyDialog_w::on_userDefinedProtocolBidirectionalCheckBox_stateChanged( int state )
{
    int i; int j;
    CurrentlySelectedUDPIndexes(i,j);
    if( i>=0 && j>=0 )
    {
        changeProtocolBi_ cpb((bool)state, j);
        firewall.ApplyToNthInClass(cpb, i, "User Defined");
    }
}

void GuardPuppyDialog_w::on_logRateSpinBox_valueChanged( int value )
{
    firewall.setLogRate( value );
}
void GuardPuppyDialog_w::on_logBurstSpinBox_valueChanged( int value )
{
    firewall.setLogRateBurst( value );
}
void GuardPuppyDialog_w::on_logWarnRateLimitSpinBox_valueChanged( int value )
{
    firewall.setLogWarnLimitRate( value );
}
void GuardPuppyDialog_w::on_localPortRangeLowSpinBox_valueChanged( int value )
{
    firewall.setLocalDynamicPortRangeStart( value );
}
void GuardPuppyDialog_w::on_localPortRangeHighSpinBox_valueChanged( int value )
{
    firewall.setLocalDynamicPortRangeEnd( value );
}

void GuardPuppyDialog_w::on_logLevelComboBox_currentIndexChanged(int value)
{
    firewall.setLogLevel(value);
}

void GuardPuppyDialog_w::on_userDefinedProtocolTypeComboBox_currentIndexChanged(int value)
{
    int i; int j;
    CurrentlySelectedUDPIndexes(i,j);
    if( i>=0 && j>=0 )
    {
        std::cerr << i << " " << j <<std::endl;
        changeProtocolType_ cpn(value == 0?IPPROTO_TCP:IPPROTO_UDP, j);
        firewall.ApplyToNthInClass(cpn, i, "User Defined");
        userDefinedProtocolTreeWidget->topLevelItem(i)->child(j)->setText(1, value == 0?"TCP":"UDP");
        userDefinedProtocolBidirectionalCheckBox->setEnabled(value);
    }
}
void GuardPuppyDialog_w::on_userDefinedProtocolNameLineEdit_textEdited(QString const & text)
{
    int i; int j;
    CurrentlySelectedUDPIndexes(i,j);
    if( i>=0 && j>=0 )
    {
        std::string s = text.toStdString();
        changeProtocolName_ cpn(s);
        firewall.ApplyToNthInClass(cpn, i, "User Defined");
        QTreeWidgetItem* t = userDefinedProtocolTreeWidget->topLevelItem(i);
        t->setText(0, s.c_str());//change the root of the protocol
        for(int c(0); c < t->childCount(); c++)
        {//and for all the children
            t->child(c)->setText(0, s.c_str());
        }
    }
}
void GuardPuppyDialog_w::on_userDefinedProtocolPortStartSpinBox_editingFinished()
{
    int i; int j;
    int value = userDefinedProtocolPortStartSpinBox->value();
    CurrentlySelectedUDPIndexes(i,j);
    if( i>=0 && j>=0 )
    {
        changeProtocolPort_ cpn(value, j, userDefinedProtocolTreeWidget->topLevelItem(i));
        firewall.ApplyToNthInClass(cpn, i, "User Defined");
        if(cpn.pChange())
            userDefinedProtocolPortEndSpinBox->setValue(value);
    }
}
void GuardPuppyDialog_w::on_userDefinedProtocolPortEndSpinBox_editingFinished()
{
    int i; int j;
    int value = userDefinedProtocolPortEndSpinBox->value();
    CurrentlySelectedUDPIndexes(i,j);
    if( i>=0 && j>=0 )
    {
        changeProtocolPort_ cpn(value, j, userDefinedProtocolTreeWidget->topLevelItem(i), false);
        firewall.ApplyToNthInClass(cpn, i, "User Defined");
        if(cpn.pChange())
            userDefinedProtocolPortStartSpinBox->setValue(value);
    }
}

