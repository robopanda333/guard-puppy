#pragma once

#include <string>
#include <vector>
#include <map>

#include <boost/foreach.hpp>
#include <boost/spirit/home/phoenix/core.hpp>
#include <boost/spirit/home/phoenix/operator.hpp>
#include <boost/spirit/home/phoenix/bind.hpp>


#include <iostream>
#include <fstream>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>

#include "protocoldb.h"
#include "iprange.h"
#include "zoneImportStrategy.h"

/*
**  Each zone maintains a list of IPaddress that define this zone and
**  a list of zone-protocol pairs this zone can communicate with.
*/

class Zone
{
public:
    enum ZoneType {LocalZone, InternetZone, UserZone};
    enum ProtocolState { PERMIT, DENY, REJECT };
private:
    std::string                name;
    std::string                comment;
    ZoneType                   zonetype;
    std::vector<IPRange>       memberMachine;
    std::map< std::string, std::map< std::string, ProtocolState > > protocols;  // [toZone][protocolName] = state
    std::vector< std::string > connections;          // List of zone names this zone is connected to, in theory, these are keys of protocols
                                                     // Though it's possible that zones are connected in name before any protocols are associated with them
public:
    Zone( Zone const & rhs ) { *this = rhs; }
    Zone( ZoneType zt ):zonetype(zt) {}
    Zone( std::string const & n, ZoneType const zt = UserZone ):name(n), zonetype(zt) {}
    ~Zone() {}
    Zone & operator=( Zone const & rhs );

    void setComment( std::string const & c )    { comment = c; }
    void setName( std::string const & n )       { name = n; }
    void setProtocolState( std::string const & zoneTo, std::string const & protocol, Zone::ProtocolState state) { protocols[ zoneTo ][ protocol ] = state; }

    std::string const & getComment() const      { return comment; }
    std::string const & getName() const         { return name; }
    ProtocolState getProtocolState( std::string const & toZone, std::string const & protocolName ) const;
    std::vector< std::string > getConnectedZoneProtocols( std::string const & toZone, ProtocolState state ) const;
    std::vector<IPRange> const & getMemberMachineList() const { return memberMachine; }

    void addMemberMachine( IPRange const & ip ) { memberMachine.push_back( ip ); }
    void renameMachine( std::string const & oldMachineName, std::string const & newMachineName );
    void deleteMemberMachine( IPRange const & ip );
    void connect( std::string const & zoneTo );
    void disconnect( std::string const & zoneTo );
    void ZoneImport(std::string const & filename);

    bool editable() const   { return !(isLocal()||isInternet()); }
    bool isLocal() const    { return zonetype==LocalZone; }
    bool isInternet() const { return zonetype==InternetZone; }
    bool isConnectedTo( std::string const & zoneName ) const;
    bool isConnectionMutable(std::string const & toZone) const;
    bool operator!=( Zone const & rhs ) const { return name != rhs.name; }
};

class ZoneDB
{
std::vector< Zone > zdb;
public:

    /*!
    **  \brief add an ipAddress to a zone
    */
    void addNewMachine( std::string const & zoneName, std::string const & ipAddress );

    /*!
    **  \brief  Delete an ipaddress from a zone
    */
    void deleteMachine( std::string const & zoneName, std::string const & ipAddress );

    /*!
    **  \brief Change the name associated with an ipaddress in a given zone
    */
    void setNewMachineName( std::string const & zoneName, std::string const & oldMachineName, std::string const & newMachineName );

    /*!
    **  \brief For a zoneFrom->zoneTo protocol, set the state to PERMIT, DENY, or REJECT
    */
    void setProtocolState( std::string const & zoneFrom, std::string const & zoneTo, std::string const & protocolName, Zone::ProtocolState state );

    /*!
    **  \brief  Get the protocol state for a given zoneFrom->zoneTo protocol
    */
    Zone::ProtocolState getProtocolState( std::string const & zoneFrom, std::string const & zoneTo, std::string const & protocolName );

    /*!
    **  \brief Get a list of all the zones
    */
    std::vector< std::string > getZoneList() const;

    /*!
    **  \brief  Return number of zones
    **
    **  \todo My guess is that places that use this could be rewritten more intelligently and this function could be removed
    */
    size_t zoneCount() const { return zdb.size(); }

    /*!
    **  \brief  Add a new zone to the firewall
    */
    void addZone( std::string const & zoneName ) { zdb.push_back( Zone( zoneName ) );}

    /*!
    **  \brief  Delete a named zone from the firewall
    */
    void deleteZone( std::string const & zoneName );

    /*!
    **  \brief get a constant reference to a zone given a name
    */
    Zone const & getZone( std::string const & name ) const;

    /*!
    **  \brief get a reference to a zone given a name
    */
    Zone & getZone( std::string const & name );

    /*!
    **  \brief Get a list of zones connected to this one
    */
    std::vector< std::string > getConnectedZones( std::string const & zoneFrom ) const;

    /*!
    **  \brief  update the connection state between zoneFrom and zoneTo
    */
    void updateZoneConnection( std::string const & zoneFrom, std::string const & zoneTo, bool connected );

    /*!
    **  \brief get a list of protocols that between zoneFrom->zoneTo
    */
    std::vector< std::string > getConnectedZoneProtocols( std::string const & zoneFrom, std::string const & zoneTo, Zone::ProtocolState state ) const;

    /*!
    **  \brief boolean whether zoneFrom is connected to zoneTo
    */
    bool areZonesConnected( std::string const & zoneFrom, std::string const & zoneTo ) const;

    /*!
    **  \brief  Rename a zone name
    **
    */
    void zoneRename( std::string const & oldZoneName, std::string const & newZoneName );
};



