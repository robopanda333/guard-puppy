
#include "zone.h"

Zone & Zone::operator=( Zone const & rhs )
{
    name          = rhs.name;
    comment       = rhs.comment;
    memberMachine = rhs.memberMachine;
    zonetype      = rhs.zonetype;
    protocols     = rhs.protocols;
    connections   = rhs.connections;
    return *this;
}
void Zone::renameMachine( std::string const & oldMachineName, std::string const & newMachineName )
{
    std::vector< IPRange >::iterator i = std::find_if( memberMachine.begin(), memberMachine.end(), boost::phoenix::bind( &IPRange::getAddress, boost::phoenix::arg_names::arg1) == oldMachineName );
    if ( i != memberMachine.end() )
        i->setAddress( newMachineName );
}
void Zone::deleteMemberMachine( IPRange const & ip )
{
    std::vector<IPRange>::iterator i = std::find( memberMachine.begin(), memberMachine.end(), ip );
    if ( i != memberMachine.end() )
        memberMachine.erase( i );
}
Zone::ProtocolState Zone::getProtocolState( std::string const & toZone, std::string const & protocolName ) const
{
    std::map< std::string, std::map< std::string, Zone::ProtocolState > >::const_iterator zit;
    zit = protocols.find( toZone );
    if ( zit == protocols.end() )
        return DENY;
    std::map< std::string, Zone::ProtocolState >::const_iterator pit;
    pit = zit->second.find( protocolName );
    if ( pit == zit->second.end() )
        return DENY;
    return pit->second;

}
std::vector< std::string > Zone::getConnectedZoneProtocols( std::string const & toZone, Zone::ProtocolState state ) const
{
    std::vector< std::string > protocolsNames;
    typedef std::map< std::string, Zone::ProtocolState > map_t;

    std::map< std::string, map_t >::const_iterator zit;
    zit = protocols.find( toZone );
    if( zit != protocols.end() )
    {
        BOOST_FOREACH( map_t::value_type const & mapEntry, zit->second )
            if(mapEntry.second == state )
            {
                protocolsNames.push_back( mapEntry.first );
            }
    }
    return protocolsNames;
}
void Zone::connect( std::string const & zoneTo )
{
    if ( !isConnectedTo( zoneTo ) )
        connections.push_back( zoneTo );
}
void Zone::disconnect( std::string const & zoneTo )
{
    if(!isConnectionMutable(zoneTo))
    {
        std::vector< std::string >::iterator i = std::find( connections.begin(), connections.end(), zoneTo );
        if ( i != connections.end() )
        {
            connections.erase( i );
        }
    }
}
bool Zone::isConnectedTo( std::string const & zoneName ) const
{
    return std::find( connections.begin(), connections.end(), zoneName ) != connections.end();
}
bool Zone::isConnectionMutable(std::string const & toZone) const
{
    return !((isLocal() && (toZone=="Internet")) || (isInternet() && (toZone=="Local")));
}
void Zone::ZoneImport(std::string const & filename)
{
    std::ifstream in(filename.c_str());
    if( in.is_open() )
    {
        ZoneImportABCstrategy * strategy = new ZoneImportP2P;
        strategy->Import(in, *this);
    }
}


void ZoneDB::addNewMachine( std::string const & zoneName, std::string const & ipAddress )
{
    Zone & zone = getZone( zoneName );
    zone.addMemberMachine( IPRange( ipAddress ) );
}
void ZoneDB::deleteMachine( std::string const & zoneName, std::string const & ipAddress )
{
    Zone & zone = getZone( zoneName );
    zone.deleteMemberMachine( IPRange( ipAddress ) );
}
void ZoneDB::setNewMachineName( std::string const & zoneName, std::string const & oldMachineName, std::string const & newMachineName )
{
    Zone & zone = getZone( zoneName );
    zone.renameMachine( oldMachineName, newMachineName );
}
void ZoneDB::setProtocolState( std::string const & zoneFrom, std::string const & zoneTo, std::string const & protocolName, Zone::ProtocolState state )
{
    Zone & zone = getZone( zoneFrom );
    return zone.setProtocolState( zoneTo, protocolName, state );
}
Zone::ProtocolState ZoneDB::getProtocolState( std::string const & zoneFrom, std::string const & zoneTo, std::string const & protocolName )
{
    Zone & zone = getZone( zoneFrom );
    return zone.getProtocolState( zoneTo, protocolName );
}
std::vector< std::string > ZoneDB::getZoneList() const
{
    std::vector< std::string > names;
    BOOST_FOREACH( Zone const & z, zdb )
        names.push_back( z.getName() );
    return names;
}
void ZoneDB::deleteZone( std::string const & zoneName )
{
    std::vector< Zone >::iterator zit = std::find_if( zdb.begin(), zdb.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == zoneName );
    if ( zit == zdb.end() )
        throw std::string("Zone not found 1");
    zdb.erase( zit );
}
Zone const & ZoneDB::getZone( std::string const & name ) const
{ 
    std::vector< Zone >::const_iterator zit = std::find_if( zdb.begin(), zdb.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == name );
    if ( zit == zdb.end() )
        throw std::string("Zone not found 2");
    return *zit;
}
Zone & ZoneDB::getZone( std::string const & name )
{
    std::vector< Zone >::iterator zit = std::find_if( zdb.begin(), zdb.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == name );
    if ( zit == zdb.end() )
        throw std::string("Zone not found 3");
    return *zit;
}
std::vector< std::string > ZoneDB::getConnectedZones( std::string const & zoneFrom ) const
{
    std::vector< std::string > connectedZones;
    BOOST_FOREACH( std::string const & zoneTo, getZoneList() )
        if ( areZonesConnected( zoneFrom, zoneTo ) )
            connectedZones.push_back( zoneTo );
    return connectedZones;
}
void ZoneDB::updateZoneConnection( std::string const & zoneFrom, std::string const & zoneTo, bool connected )
{
    if ( connected )
        getZone( zoneFrom ).connect( zoneTo );
    else
        getZone( zoneFrom ).disconnect( zoneTo );
}
std::vector< std::string > ZoneDB::getConnectedZoneProtocols( std::string const & zoneFrom, std::string const & zoneTo, Zone::ProtocolState state ) const
{
    return getZone( zoneFrom ).getConnectedZoneProtocols( zoneTo, state );
}
bool ZoneDB::areZonesConnected( std::string const & zoneFrom, std::string const & zoneTo ) const
{
    try
    {
        Zone const & zone = getZone( zoneFrom );
        return zone.isConnectedTo( zoneTo );
    }
    catch (...)
    {
        return false;
    }
}

