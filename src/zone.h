#pragma once

#include <string>
#include <vector>
#include <map>

#include <boost/foreach.hpp>
#include <boost/spirit/home/phoenix/core.hpp>
#include <boost/spirit/home/phoenix/operator.hpp>
#include <boost/spirit/home/phoenix/bind.hpp>

#include "protocoldb.h"
#include "iprange.h"
#include "zoneImportStrategy.h"

#include <iostream>
#include <fstream>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>

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
                                                     // Though it's possible that zones are connected in name before any protocols are associated
                                                     // with them.
                                                     //! \todo Might be something to examine in the future.
    //  id, nextId are used to assign integers to zones.  Probably not needed
    //  as zone name could be used instead.  Too early to remove though.
    unsigned int               id;
    static unsigned int        nextId;
public:

    Zone( Zone const & rhs )
    {
        *this = rhs;
    }

    Zone( ZoneType zt )
    {
        zonetype = zt;
        id = nextId++;
    }

    Zone( std::string const & zoneName, ZoneType zt = UserZone )
     : name( zoneName ), zonetype( zt )
    {
        id = nextId++;
    }

    ~Zone()
    {
    }

    Zone & operator=( Zone const & rhs )
    {
        name          = rhs.name;
        comment       = rhs.comment;
        memberMachine = rhs.memberMachine;
        zonetype      = rhs.zonetype;
        protocols     = rhs.protocols;
        id            = rhs.id;

        connections   = rhs.connections;
        return *this;
    }

    unsigned int getId() const { return id; }

    void renameMachine( std::string const & oldMachineName, std::string const & newMachineName )
    {
        std::vector< IPRange >::iterator i = std::find_if( memberMachine.begin(), memberMachine.end(), boost::phoenix::bind( &IPRange::getAddress, boost::phoenix::arg_names::arg1) == oldMachineName );

        if ( i != memberMachine.end() )
            i->setAddress( newMachineName );
    }

    void setComment( std::string const & c )
    {
        comment = c;
    }

    std::string const & getComment() const
    {
        return comment;
    }

    void setName( std::string const & n )
    {
        name = n;
    }
    std::string const & getName() const
    {
        return name;
    }

    std::vector<IPRange> const & getMemberMachineList() const
    {
        return memberMachine;
    }

    void addMemberMachine( IPRange const & ip )
    {
        memberMachine.push_back( ip );
    }

    void deleteMemberMachine( IPRange const & ip )
    {
        std::vector<IPRange>::iterator i = std::find( memberMachine.begin(), memberMachine.end(), ip );
        if ( i != memberMachine.end() )
            memberMachine.erase( i );
    }

    bool operator!=( Zone const & rhs ) const
    {
        return name != rhs.name;
    }

    void setProtocolState( std::string const & zoneTo, std::string const & protocol, Zone::ProtocolState state)
    {
        protocols[ zoneTo ][ protocol ] = state;
    }

    bool editable() const
    {
        return !(isLocal()||isInternet());
    }

    ProtocolState getProtocolState( std::string const & toZone, std::string const & protocolName ) const
    {
        std::map< std::string, std::map< std::string, ProtocolState > >::const_iterator zit;
        zit = protocols.find( toZone );
        if ( zit == protocols.end() )
            return DENY;
        std::map< std::string, ProtocolState >::const_iterator pit;
        pit = zit->second.find( protocolName );
        if ( pit == zit->second.end() )
            return DENY;
        return pit->second;

    }

    std::vector< std::string > getConnectedZoneProtocols( std::string const & toZone, ProtocolState state ) const
    {
        std::vector< std::string > protocolsNames;
        typedef std::map< std::string, ProtocolState > map_t;

        std::map< std::string, map_t >::const_iterator zit;
        zit = protocols.find( toZone );
        if( zit != protocols.end() )
            BOOST_FOREACH( map_t::value_type const & mapEntry, zit->second )
                if(mapEntry.second == state )
                    protocolsNames.push_back( mapEntry.first );
        return protocolsNames;
    }

    void denyAllProtocols( Zone const & toZone )
    {
        if ( protocols.find( toZone.name ) != protocols.end() )
            protocols[ toZone.name ].clear();
    }

    bool isLocal() const
    {
        return zonetype==LocalZone;
    }

    bool isInternet() const
    {
        return zonetype==InternetZone;
    }

    void connect( std::string const & zoneTo )
    {
        if ( !isConnectedTo( zoneTo ) )
            connections.push_back( zoneTo );
    }

    void disconnect( std::string const & zoneTo )
    {
        if(!isConnectionMutable(zoneTo))
        {
            std::vector< std::string >::iterator i = std::find( connections.begin(), connections.end(), zoneTo );
            if ( i != connections.end() )
                connections.erase( i );
        }
    }

    bool isConnectedTo( std::string const & zoneName ) const
    {
        return std::find( connections.begin(), connections.end(), zoneName ) != connections.end();
    }

    bool isConnectionMutable(std::string const & toZone)
    {
        return !((isLocal() && (toZone=="Internet")) || (isInternet() && (toZone=="Local")));
    }

    bool isConnectionMutable(Zone const & toZone)
    {
        return !((isLocal() && toZone.isInternet())||(isInternet() && toZone.isLocal()));
    }

    void ZoneImport(std::string const & filename)
    {
        std::ifstream in(filename.c_str());
        if( in.is_open() )
        {
            ZoneImportABCstrategy * strategy = new ZoneImportP2P;
            strategy->Import(in, *this);
        }
    }
};

