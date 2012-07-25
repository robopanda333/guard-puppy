#pragma once

/*!
**  This file and the accompanying GuardPuppyFirewall class implement
**  the structures needed to generate a iptables script.
**
**  The core abstraction in the firewall is that communication happens
**  between two zones.  This is a directional relationship.
**
**  Each zone maintains a list of zone-protocol pairs that it is allowed
**  to communicate with.
*/

#include <fstream>
#include <iostream>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/spirit/home/phoenix/core.hpp>
#include <boost/spirit/home/phoenix/operator.hpp>
#include <boost/spirit/home/phoenix/bind.hpp>

#include "protocoldb.h"
#include "zone.h"

//#define SYSTEM_RC_FIREWALL "/etc/rc.firewall"
#define SYSTEM_RC_FIREWALL2 "/etc/rc2.firewall"   //  This is temporary during development so that guardpuppy doesn't actually overwrite rc.firewall

//! \todo These are values of logging.  However, there is a whole matching mechanism
//!       in iptables for logging filters and rules that could be implemented.

//! \todo For now, removing the "modified" detection mechanism.  It doesn't feel quite right to be at this level.

//! \todo Read in existing iptables state to determine configuration rather than the rc.firewall script

//! \todo There are two paradigms used throughout, the client/server and the from/to  Clients *ALWAYS* are from and servers are to.  This is quite
//!       confusing and would benefit from switching completely to one or the other, probably from/to.
//        server = to
//        client = from

enum { LOG_ALL_OR_UNMATCHED, LOG_FIRST, LOG_ALL_KNOWN_MATCHED };

class GuardPuppyFireWall
{
    ProtocolDB & pdb;                // The protocol database we are using.
    bool waspreviousfirewall;       // True if there was a previous Guarddog firewall active/available
                                    // When GuardPuppy exists, know whether to restore rc.firewall from rc.firewall~ or not
                                    // at program startup.
    bool systemfirewallmodified;    // True if the current state of the system has been modified
                                    // since program startup. This is needed at 'Cancel' time when
                                    // we need to decide if we have any 'Apply'ed changes that need
                                    // to be undone.

    bool superUserMode;             // True if GuardPuppy is running as root

    enum LogRateUnit {SECOND=0, MINUTE, HOUR, DAY};

    std::vector< Zone > zones;

    uint localPortRangeStart;
    uint localPortRangeEnd;
    bool disabled;
    bool routing;

    bool logdrop;
    bool logreject;
    bool logipoptions;
    bool logtcpoptions;
    bool logtcpsequence;
    bool logabortedtcp;
    uint loglevel;
    bool logratelimit;
    uint lograte;
    LogRateUnit lograteunit;
    uint lograteburst;
    bool logwarnlimit;
    uint logwarnrate;
    LogRateUnit logwarnrateunit;
    bool dhcpcenabled;
    std::string dhcpcinterfacename;
    bool dhcpdenabled;
    std::string dhcpdinterfacename;
    bool allowtcptimestamps;

//  time to get serious
//    std::vector< UserDefinedProtocol > userdefinedprotocols;

public:
    std::string description;


    /*!
    ** \brief Get the protocol description given a name of a protocol
    */
    std::string getProtocolText( std::string const & protocol )
    {
        std::string text = "Not found";
        try
        {
            text = pdb.lookup( protocol ).description;
        }
        catch(...)
        {
        }
        return text;
    }

    //! \todo My guess is none of the checkboxes on the GUI are connected to these calls yet
    void setLogDrop(bool on) { logdrop = on; }
    bool isLogDrop() { return logdrop; }
    void setLogReject(bool on) { logreject = on; }
    bool isLogReject() { return logreject; }
    void setLogIPOptions(bool on) { logipoptions = on; }
    bool isLogIPOptions() { return logipoptions; }
    void setLogTCPOptions(bool on) { logtcpoptions = on; }
    bool isLogTCPOptions() { return logtcpoptions; }
    void setLogTCPSequence(bool on) { logtcpsequence = on; }
    bool isLogTCPSequence() { return logtcpsequence; }
    void setLogAbortedTCP(bool on) { logabortedtcp = on; }
    bool isLogAbortedTCP() { return logabortedtcp; }
    void setLogLevel(uint level) { loglevel = level; }
    uint getLogLevel() { return loglevel; }
    void setLogRateLimit(bool on) { logratelimit = on; }
    bool isLogRateLimit() { return logratelimit; }
    void setLogRate(uint hitsper) { lograte = hitsper; }
    uint getLogRate() { return lograte; }
    void setLogRateUnit(LogRateUnit unit) { lograteunit = unit; }
    LogRateUnit getLogRateUnit() { return lograteunit; }
    void setLogRateBurst(uint burst) { lograteburst = burst; }
    uint getLogRateBurst() { return lograteburst; };
    void setLogWarnLimit(bool on) { logwarnlimit = on; }
    bool isLogWarnLimit() { return logwarnlimit; }
    void setLogWarnLimitRate(uint hitsper) { logwarnrate = hitsper; }
    uint getLogWarnLimitRate() { return logwarnrate; }
    void setLogWarnLimitRateUnit(LogRateUnit unit) { logwarnrateunit = unit; }
    LogRateUnit getLogWarnLimitRateUnit() { return logwarnrateunit; }
    void setDHCPcEnabled(bool on) { dhcpcenabled = on; }
    bool isDHCPcEnabled() { return dhcpcenabled; }
    void setDHCPdEnabled(bool on) { dhcpdenabled = on; }
    bool isDHCPdEnabled() { return dhcpdenabled; }
    void setAllowTCPTimestamps(bool on) { allowtcptimestamps = on; }
    bool isAllowTCPTimestamps() { return allowtcptimestamps; }

    /*!
    **  \brief add an ipAddress to a zone
    */
    void addNewMachine( std::string const & zoneName, std::string const & ipAddress )
    {
        Zone & zone = getZone( zoneName );

        zone.addMemberMachine( IPRange( ipAddress ) );
    }

    /*!
    **  \brief  Delete an ipaddress from a zone
    */
    void deleteMachine( std::string const & zoneName, std::string const & ipAddress )
    {
        Zone & zone = getZone( zoneName );

        zone.deleteMemberMachine( IPRange( ipAddress ) );
    }

    /*!
    **  \brief Change the name associated with an ipaddress in a given zone
    */
    void setNewMachineName( std::string const & zoneName, std::string const & oldMachineName, std::string const & newMachineName )
    {
        Zone & zone = getZone( zoneName );

        zone.renameMachine( oldMachineName, newMachineName );
    }

    /*!
    **  \brief For a zoneFrom->zoneTo protocol, set the state to PERMIT, DENY, or REJECT
    */
    void setProtocolState( std::string const & zoneFrom, std::string const & zoneTo, std::string const & protocolName, Zone::ProtocolState state )
    {
        Zone & zone = getZone( zoneFrom );

        return zone.setProtocolState( zoneTo, protocolName, state );
    }

    /*!
    **  \brief  Get the protocol state for a given zoneFrom->zoneTo protocol
    */
    Zone::ProtocolState getProtocolState( std::string const & zoneFrom, std::string const & zoneTo, std::string const & protocolName )
    {
        Zone & zone = getZone( zoneFrom );

        return zone.getProtocolState( zoneTo, protocolName );
    }

    /*!
    **  \brief Get a list of all the zones
    */
    std::vector< std::string > getZoneList() const
    {
        std::vector< std::string > names;
        BOOST_FOREACH( Zone const & z, zones )
        {
            names.push_back( z.getName() );
        }
        return names;
    }

    /*!
    **  \brief  Return number of zones
    **
    **  \todo My guess is that places that use this could be rewritten more intelligently and this function could be removed
    */
    size_t zoneCount() const { return zones.size(); }


    /*!
    **  \brief  Add a new zone to the firewall
    */
    void addZone( std::string const & zoneName )
    {
        zones.push_back( Zone( zoneName ) );
    }

    /*!
    **  \brief  Delete a named zone from the firewall
    */
    void deleteZone( std::string const & zoneName )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == zoneName );
        if ( zit == zones.end() )
        {
            throw std::string("Zone not found 1");
        }
        zones.erase( zit );
    }

    /*!
    **  \brief get a constant reference to a zone given a name
    */
    Zone const & getZone( std::string const & name ) const
    {
        std::vector< Zone >::const_iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == name );
        if ( zit == zones.end() )
        {
            throw std::string("Zone not found 2");
        }
        return *zit;
    }
    /*!
    **  \brief get a reference to a zone given a name
    */
    Zone & getZone( std::string const & name )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == name );
        if ( zit == zones.end() )
        {
            throw std::string("Zone not found 3");
        }
        return *zit;
    }

    /*!
    **  \brief Get a list of zones connected to this one
    */
    std::vector< std::string > getConnectedZones( std::string const & zoneFrom ) const
    {
        std::vector< std::string > connectedZones;

        BOOST_FOREACH( std::string const & zoneTo, getZoneList() )
        {
            if ( areZonesConnected( zoneFrom, zoneTo ) )
            {
                connectedZones.push_back( zoneTo );
            }
        }

        return connectedZones;
    }

    /*!
    **  \brief  update the connection state between zoneFrom and zoneTo
    */
    void updateZoneConnection( std::string const & zoneFrom, std::string const & zoneTo, bool connected )
    {
        if ( connected )
        {
            getZone( zoneFrom ).connect( zoneTo );
        }
        else
        {
            getZone( zoneFrom ).disconnect( zoneTo );
        }
    }

    /*!
    **  \brief get a list of protocols that between zoneFrom->zoneTo
    */
    std::vector< std::string > getConnectedZoneProtocols( std::string const & zoneFrom, std::string const & zoneTo, Zone::ProtocolState state ) const
    {
        return getZone( zoneFrom ).getConnectedZoneProtocols( zoneTo, state );
    }

    /*!
    **  \brief boolean whether zoneFrom is connected to zoneTo
    */
    bool areZonesConnected( std::string const & zoneFrom, std::string const & zoneTo ) const
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

    /*!
    **  \brief  Rename a zone name
    **
    */
    void zoneRename( std::string const & oldZoneName, std::string const & newZoneName )
    {
        Zone & zone = getZone( oldZoneName );
        zone.setName( newZoneName );
    }

// This function is already dead
//  /*!
//  **  \brief Adds a new UDP with the given information
//  */
//  void newUserDefinedProtocol(std::string name, uchar udpType, uint udpStartPort, uint udpEndPort, bool bi)
//  { //we still have udps, we just will not access them the same way. This function will likely go away
//      pdb.UserDefinedProtocol(name, udpType, udpStartPort, udpEndPort, bi);
//  }

// This function is already dead
//  /*!
//  **  \brief Deletes a User Defined Protocol
//  **
//  */
//  void deleteUserDefinedProtocol( std::string i )
//  {
//      pdb.deleteProtocolEntry(i);
//  }

    /*!
    **
    ** \todo Need to throw exception if things don't work.  One case would
    **      be if the networkprotocol database file cannot be loaded.
    */
    GuardPuppyFireWall( bool superuser, ProtocolDB & _pdb)
        : pdb( _pdb ), superUserMode( superuser )
    {
        try
        {
            factoryDefaults();
            openDefault();
        }
        catch ( std::string const & msg )
        {
            std::cerr << "Exception: " << msg << std::endl;
        }
    }

    void setDisabled(bool on)
    {
        disabled = on;
    }

    bool isDisabled()
    {
        return disabled;
    }

    void setLocalDynamicPortRangeStart(uint start)
    {
        localPortRangeStart = start;
    }
    void setLocalDynamicPortRangeEnd( uint end )
    {
        localPortRangeEnd = end;
    }

    void getLocalDynamicPortRange(uint &start,uint &end)
    {
        start = localPortRangeStart;
        end = localPortRangeEnd;
    }

    void setDHCPcInterfaceName(const std::string &ifacename)
    {
        dhcpcinterfacename = ifacename;
    }

    std::string getDHCPcInterfaceName()
    {
        return dhcpcinterfacename;
    }

    void setDHCPdInterfaceName(const std::string &ifacename)
    {
        dhcpdinterfacename = ifacename;
    }

    std::string getDHCPdInterfaceName()
    {
        return dhcpdinterfacename;
    }

    bool isSuperUserMode() const
    {
        return superUserMode;
    }

    /*!
    **  \brief if the current firewall state is modified, save the
    **         new rc.firewall file and apply it.
    */
    void saveAndApply()
    {
        //! \todo Restore this in the real version, once we know the produced script is correct
        //        std::string filename( SYSTEM_RC_FIREWALL );
        std::string filename( SYSTEM_RC_FIREWALL2 );
        std::cout << "Saving firewall " << filename << std::endl;

        save( filename );
        apply();
    }

    ///////////////////////////////////////////////////////////////////////////

    /*!
    **  \brief  Write the firewall to a temporary file and execute it.
    */
    void apply()
    {
        boost::filesystem::path tmpFile = boost::filesystem::unique_path();
        std::string tmp( "/tmp/" );
        tmp += tmpFile.string();
        save( tmp );
        std::string cmd = "chmod 0700 " + tmp;
        system( cmd.c_str() );
        runFirewall( tmp );
        boost::filesystem::remove( tmp );
    }

    void copyFile( std::string const & src,  std::string const & dest )
    {
#if BOOST_FILESYSTEM_VERSION < 3
        //! \todo Not sure what this behavior is, i.e. over write or not.  Probably remove in final version and
        //  require v3
        boost::filesystem::copy_file( src, dest );
#else
        boost::filesystem::copy_file( src, dest, boost::filesystem::copy_option::overwrite_if_exists );
#endif
    }

    /*!
    **  \brief  Open the /etc/rc.firewall script if executing as superuser
    */
    void openDefault()
    {
        std::string filename( SYSTEM_RC_FIREWALL2 );
        std::ifstream fileinfo( SYSTEM_RC_FIREWALL2  );

        if ( superUserMode==false )
        {
            return; // Sorry, if you are not root then you get no default firewall.
        }

        if ( boost::filesystem::exists( SYSTEM_RC_FIREWALL2 ) )
        {
            // Backup the firewall.
            copyFile( SYSTEM_RC_FIREWALL2, SYSTEM_RC_FIREWALL2 "~" );

            //  There is an rc.firewall file, but don't know if it's in a format GuardPuppy knows
            waspreviousfirewall = true;

            try
            {
                readFirewall( filename );
            }
            catch(...)
            {
                waspreviousfirewall = false;
                factoryDefaults();
            }

        }
        else
        {
            // rc.firewall doesn't exists, so initialize a blank slate
            waspreviousfirewall = false;
            factoryDefaults();
        }
    }

    std::vector< ProtocolNetUse > getNetworkUse( std::string const & protocolName ) const
    {
        std::vector< ProtocolNetUse > protos = pdb.getNetworkUses( protocolName );
        return protos;
    }

    /*!
    **  \brief Save firewall to filename
    */
    void save( std::string const & filename )
    {
        std::ofstream stream( filename.c_str() );
        //! \todo Update permissions to be secure chmod 0700 ?

        int c,oldc;

        stream<<"#!/bin/bash\n"
            "# [GuardPuppy]\n"
            "# DO NOT EDIT!\n"
            "# This firewall script was generated by \"guard-puppy\" \n"
            "# https://github.com/SamAxe/guard-puppy.  This script requires iptables\n"
            "#\n"
            "# [Description]\n";
        c = 0;
        oldc = 0;
        while((c = description.find('\n',c))>=0) {
            stream<<"#  "<<description.substr(oldc,c-oldc)<<"\n";
            oldc = c + 1;
            c++;
        }
        c = (int)description.length();
        stream<<"#  "<<description.substr(oldc,c-oldc)<<"\n";

        stream<<
            "# [Config]\n"
            "# LOCALPORTRANGESTART="<<localPortRangeStart<<"\n"
            "# LOCALPORTRANGEEND="<<localPortRangeEnd<<"\n"
            "# DISABLED="<<(disabled?1:0)<<"\n"
            "# LOGREJECT="<<(logreject?1:0)<<"\n"
            "# LOGDROP="<<(logdrop?1:0)<<"\n"
            "# LOGABORTEDTCP="<<(logabortedtcp?1:0)<<"\n"
            "# LOGIPOPTIONS="<<(logipoptions?1:0)<<"\n"
            "# LOGTCPOPTIONS="<<(logtcpoptions?1:0)<<"\n"
            "# LOGTCPSEQUENCE="<<(logtcpsequence?1:0)<<"\n"
            "# LOGLEVEL="<<(loglevel)<<"\n"
            "# LOGRATELIMIT="<<(logratelimit?1:0)<<"\n"
            "# LOGRATE="<<lograte<<"\n"
            "# LOGRATEUNIT="<<((uint)lograteunit)<<"\n"
            "# LOGRATEBURST="<<lograteburst<<"\n"
            "# LOGWARNLIMIT="<<(logwarnlimit?1:0)<<"\n"
            "# LOGWARNRATE="<<logwarnrate<<"\n"
            "# LOGWARNRATEUNIT="<<((uint)logwarnrateunit)<<"\n"
            "# DHCPC="<<(dhcpcenabled?1:0)<<"\n"
            "# DHCPCINTERFACENAME="<<(dhcpcinterfacename)<<"\n"
            "# DHCPD="<<(dhcpdenabled?1:0)<<"\n"
            "# DHCPDINTERFACENAME="<<(dhcpdinterfacename)<<"\n"
            "# ALLOWTCPTIMESTAMPS="<<(allowtcptimestamps?1:0)<<"\n";

        // Output the info about the Zones we have. No need to output the default zones.
        BOOST_FOREACH( Zone & zit, zones )
        {
            if(zit.editable())
            {
                stream<<"# [Zone]\n";
                stream<<"# NAME="<<(zit.getName().c_str())<<"\n";
                stream<<"# COMMENT="<<(zit.getComment())<<"\n";
                BOOST_FOREACH( IPRange const & addy, zit.getMemberMachineList() )
                {
                    stream<<"# ADDRESS="<<addy.getAddress()<<"\n";
                }
            }
        }

        // Output the User Defined Protocols
        {//kill the functor we don't care about it after it does it's work.
            OutputUDP OutputUDPm(stream);
            pdb.ApplyToDB(OutputUDPm);
        }
        // Go over each Zone and output which protocols are allowed to whom.
        BOOST_FOREACH( Zone const & toZone, zones )
        {
            stream<<"# [ToZone] "<<(toZone.getName().c_str())<<"\n";

            // Iterate over each possible client zone.
            BOOST_FOREACH( Zone const & fromZone , zones )
            {
                if ( toZone != fromZone )
                {
                    stream << "# [FromZone] " << fromZone .getName() <<"\n";

                    if ( areZonesConnected( fromZone.getName(), toZone.getName()) )
                    {
                        stream<<"# CONNECTED=1\n";
                        // Now we iterate over and output each enabled protocol.
                        //                    protodictit = toZone.newPermitProtocolZoneIterator(fromZone );
                        std::vector< std::string > zones1 = getConnectedZoneProtocols( fromZone.getName(), toZone .getName(), Zone::PERMIT );
                        BOOST_FOREACH( std::string const & p, zones1 )
                        {
                            stream << "# PROTOCOL=" << p << std::endl;
                        }

                        // Output each Rejected protocol.
                        std::vector< std::string > zones2 = getConnectedZoneProtocols( fromZone.getName(), toZone .getName(), Zone::REJECT );
                        BOOST_FOREACH( std::string const & p, zones2 )
                        {
                            stream << "# REJECT=" << p << std::endl;
                        }
                    }
                    else
                    {
                        // This server/client zone combo is not currently connected.
                        stream<<"# CONNECTED=0\n";
                    }
                }
            }
        }

        // The real script starts here.
        stream<<"# [End]\n"
            "\n"
            "# Real code starts here\n"
            "# If you change the line below then also change the # DISABLED line above.\n";
        if(disabled)
        {
            stream<<"DISABLE_GUARDDOG=1\n";
        }
        else
        {
            stream<<"DISABLE_GUARDDOG=0\n";
        }
        stream<<"if test -z $GUARDDOG_VERBOSE; then\n"
            "  GUARDDOG_VERBOSE=0\n"
            "fi;\n"
            "if [ $DISABLE_GUARDDOG -eq 0 ]; then\n"
            "# Set the path\n"
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin\n"
            "# Detect which filter command we should use.\n"
            "FILTERSYS=0\n"
            "# 0 = unknown, 2 = iptables\n"
            "# Check for iptables support.\n"
            "  if [ -e /sbin/iptables ]; then\n"
            "    FILTERSYS=2\n"
            "  fi;\n"
            "  if [ -e /usr/sbin/iptables ]; then\n"
            "    FILTERSYS=2\n"
            "  fi;\n"
            "  if [ -e /usr/local/sbin/iptables ]; then\n"
            "    FILTERSYS=2\n"
            "  fi;\n"
            "if [ $FILTERSYS -eq 0 ]; then\n"
            "  logger -p auth.info -t guarddog \"ERROR Can't determine the firewall command! (Is iptables installed?)\"\n"
            "  [ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<< ("ERROR Can't determine the firewall command! (Is iptables installed?)")<<"\"\n"
            "  false\n"
            "fi;\n"
            "if [ $FILTERSYS -eq 2 ]; then\n";
        writeIPTablesFirewall(stream);
        stream<<"fi;\n"
            "fi;\n" // Matches the disable firewall IF.
            "true\n";
    }
private:
    
    //helper functor for save
    class OutputUDP
    {
        std::ofstream & o;
        public:
        OutputUDP(std::ofstream & _o):o(_o)
        {}
        void operator()(ProtocolEntry const & i)
        {
            if(i.Classification == "User Defined")
            {
                o<<"# [UserDefinedProtocol]\n";
                o<<"# ID="<<("0"/*currentudp.getID()*/)<<"\n";
                o<<"# NAME="<<(i.getName())<<"\n";

                std::vector<uchar> types = i.getTypes();
                std::vector<uint> start = i.getStartPorts();
                std::vector<uint> end = i.getEndPorts();
                std::vector<bool> bi = i.getBidirectionals();
                for(uint j(0); j < types.size(); j++)
                {
                    o<<"# TYPE="<<(types[j]==IPPROTO_TCP ? "TCP" : "UDP")<<"\n";
                    o<<"# PORT="<< start[j]<<":"<< end[j]<<"\n";
                    o<<"# BIDIRECTIONAL="<<(bi[j] ? 1 : 0)<<"\n";
                }
            }
        }
    };

    /*!
    **  \brief Helper function for writing firewall
    */
    void writeIPTablesFirewall(std::ostream &stream)
    {
        PortRangeInfo localPRI;
        const char *rateunits[] = {"second", "minute", "hour", "day" };

        stream<<"###############################\n"
            "###### iptables firewall ######\n"
            "###############################\n"
            "logger -p auth.info -t guarddog Configuring iptables firewall now.\n"
            "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Using iptables.")<<"\"\n"
            "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Resetting firewall rules.")<<"\"\n"
            "# Shut down all traffic ipv4 and ipv6\n"
            "iptables -P FORWARD DROP\n"
            "iptables -P INPUT DROP\n"
            "iptables -P OUTPUT DROP\n"
            "ip6tables -P FORWARD DROP\n"
            "ip6tables -P INPUT DROP\n"
            "ip6tables -P OUTPUT DROP\n"
            "\n"
            "# Delete any existing chains, ipv4 and ipv6\n"
            "iptables -F\n"
            "iptables -X\n"
            "ip6tables -F\n"
            "ip6tables -X\n"
            "\n"
            "# Load any special kernel modules.\n"
            "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Loading kernel modules.")<<"\"\n";


        std::vector< std::string > modules;
        BOOST_FOREACH( std::string const & m, modules )
        {
            // Output the modprobe code to load the extra modules.
            stream << "modprobe " << m << std::endl;
        }

        stream<<"\n"
            "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Setting kernel parameters.")<<"\"\n"
            "# Turn on kernel IP spoof protection\n"
            "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2> /dev/null\n"
            "# Set the TCP timestamps config\n"
            "echo "<<(allowtcptimestamps ? "1" : "0")<<" > /proc/sys/net/ipv4/tcp_timestamps 2> /dev/null\n"
            "# Enable TCP SYN Cookie Protection if available\n"
            "test -e /proc/sys/net/ipv4/tcp_syncookies && echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2> /dev/null\n"
            "echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route 2> /dev/null\n"
            "echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route 2> /dev/null\n"
            "# Log truly weird packets.\n"
            "echo 1 > /proc/sys/net/ipv4/conf/all/log_martians 2> /dev/null\n"
            "echo 1 > /proc/sys/net/ipv4/conf/default/log_martians 2> /dev/null\n"
            "# Switch the current language for a moment\n"
            "GUARDDOG_BACKUP_LANG=$LANG\n"
            "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
            "LANG=en_US\n"
            "LC_ALL=en_US\n"
            "export LANG\n"
            "export LC_ALL\n"
            "# Set kernel rp_filter. NICs used for IPSEC should not have rp_fitler turned on.\n"
            "# Find the IPs of any ipsecX NICs\n"
            "IPSEC_IPS=\"`ifconfig | gawk '/^ipsec\\w/ { grabip = 1}\n"
            "/inet addr:[[:digit:]\\\\.]+/ { if(grabip==1) printf \\\"%s \\\",gensub(/^.*inet addr:([[:digit:]\\\\.]+).*$/,\\\"\\\\\\\\1\\\",\\\"g\\\",$0)\n"
            "grabip = 0}'`\"\n"
            "# Build a list of NIC names and matching IPs\n"
            "IP_NIC_PAIRS=\"`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\\\"\\\\\\\\1\\\",\\\"g\\\",$1)}\n"
            "/inet addr:.*/ {match($0,/inet addr:[[:digit:]\\.]+/)\n"
            "ip=substr($0,RSTART+10,RLENGTH-10)\n"
            "printf \\\"%s_%s\\\\n\\\",nic,ip }'`\"\n"
            "\n"
            "# Restore the language setting\n"
            "LANG=$GUARDDOG_BACKUP_LANG\n"
            "LC_ALL=$GUARDDOG_BACKUP_LC_ALL\n"
            "export LANG\n"
            "export LC_ALL\n"
            "\n"
            "# Activate rp_filter for each NIC, except for NICs that are using\n"
            "# an IP that is involved with IPSEC.\n"
            "for X in $IP_NIC_PAIRS ; do\n"
            "  NIC=\"`echo \\\"$X\\\" | cut -f 1 -d _`\"\n"
            "  IP=\"`echo \\\"$X\\\" | cut -f 2 -d _`\"\n"
            "  RPF=\"1\"\n"
            "  for SEC_IP in $IPSEC_IPS ; do\n"
            "    if [[ $SEC_IP == $IP ]]; then\n"
            "      RPF=\"0\"\n"
            "    fi\n"
            "  done\n"
            "  echo $RPF > /proc/sys/net/ipv4/conf/$NIC/rp_filter 2> /dev/null\n"
            "done\n"
            "\n"
            "echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter 2> /dev/null\n"
            "echo \""<<localPortRangeStart<<" "<<localPortRangeEnd<<"\" > /proc/sys/net/ipv4/ip_local_port_range 2> /dev/null\n"
            "\n"
            "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Configuring firewall rules.")<<"\"\n"
            "# Set up our logging and packet 'executing' chains\n";

        // Rate limited logging rules.
        // The drop rule first.
        stream<<"iptables -N logdrop2\n";
        if(logdrop)
        {
            stream<<"iptables -A logdrop2 -j LOG --log-prefix \"DROPPED \" --log-level "<<loglevel<<" ";
            if(logipoptions)
            {
                stream<<"--log-ip-options ";
            }
            if(logtcpoptions)
            {
                stream<<"--log-tcp-options ";
            }
            if(logtcpsequence)
            {
                stream<<"--log-tcp-sequence ";
            }
            stream<<"\n";
        }
        stream<<"iptables -A logdrop2 -j DROP\n";
        stream<<"iptables -N logdrop\n";
        if(logdrop && logratelimit)
        {
            stream<<"iptables -A logdrop -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logdrop2\n";
            if(logwarnlimit)
            {
                stream<<"iptables -A logdrop -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
            }
            stream<<"iptables -A logdrop -j DROP\n";
        }
        else
        {
            stream<<"iptables -A logdrop -j logdrop2\n";
        }

        // Packet rejecting rules & more logging.
        stream<<"iptables -N logreject2\n";
        if(logreject)
        {
            stream<<"iptables -A logreject2 -j LOG --log-prefix \"REJECTED \" --log-level "<<loglevel<<" ";
            if(logipoptions)
            {
                stream<<"--log-ip-options ";
            }
            if(logtcpoptions)
            {
                stream<<"--log-tcp-options ";
            }
            if(logtcpsequence)
            {
                stream<<"--log-tcp-sequence ";
            }
            stream<<"\n";
        }
        stream<<"iptables -A logreject2 -p tcp -j REJECT --reject-with tcp-reset\n"
            "iptables -A logreject2 -p udp -j REJECT --reject-with icmp-port-unreachable\n"
            "iptables -A logreject2 -j DROP\n";
        stream<<"iptables -N logreject\n";
        if(logreject && logratelimit)
        {
            stream<<"iptables -A logreject -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logreject2\n";
            if(logwarnlimit)
            {
                stream<<"iptables -A logreject -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
            }
            stream<<"iptables -A logreject -p tcp -j REJECT --reject-with tcp-reset\n"
                "iptables -A logreject -p udp -j REJECT --reject-with icmp-port-unreachable\n"
                "iptables -A logreject -j DROP\n";
        }
        else
        {
            stream<<"iptables -A logreject -j logreject2\n";
        }

        // Logging Aborted TCP.
        if(logabortedtcp)
        {
            stream<<"iptables -N logaborted2\n"
                "iptables -A logaborted2 -j LOG --log-prefix \"ABORTED \" --log-level "<<loglevel<<" ";
            if(logipoptions)
            {
                stream<<"--log-ip-options ";
            }
            if(logtcpoptions)
            {
                stream<<"--log-tcp-options ";
            }
            if(logtcpsequence)
            {
                stream<<"--log-tcp-sequence ";
            }
            stream<<"\n";
            // Put this rule here so that we don't return from this chain
            // and interfer with any Rate Limit warnings.
            stream<<"iptables -A logaborted2 -m state --state ESTABLISHED,RELATED -j ACCEPT\n";

            stream<<"iptables -N logaborted\n";
            if(logratelimit)
            {
                stream<<"iptables -A logaborted -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logaborted2\n";
                if(logwarnlimit)
                {
                    stream<<"iptables -A logaborted -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
                }
            }
            else
            {
                stream<<"iptables -A logaborted -j logaborted2\n";
            }
        }

        stream<<"\n"
            "# Allow loopback traffic.\n"
            "iptables -A INPUT -i lo -j ACCEPT\n"
            "iptables -A OUTPUT -o lo -j ACCEPT\n";

        if(dhcpcenabled)
        {
            std::vector< std::string > dhcpclientinterfaces;
            boost::split(dhcpclientinterfaces, dhcpcinterfacename, boost::is_any_of(", "), boost::token_compress_on);

            stream << "\n" "# Allow DHCP clients.\n";
            BOOST_FOREACH( std::string const & i, dhcpclientinterfaces )
            {
                stream << "iptables -A INPUT -i "<< i <<" -p udp --dport 68 --sport 67 -j ACCEPT\n"
                    "iptables -A OUTPUT -o " << i <<" -p udp --dport 67 --sport 68 -j ACCEPT\n";
            }
        }

        if(dhcpdenabled)
        {
            std::vector< std::string > dhcpserverinterfaces;
            boost::split(dhcpserverinterfaces, dhcpdinterfacename, boost::is_any_of(", "), boost::token_compress_on);

            stream<<"\n" "# Allow DHCP servers.\n";
            BOOST_FOREACH( std::string const & i, dhcpserverinterfaces )
            {
                stream << "iptables -A INPUT -i " << i << " -p udp --dport 67 --sport 68 -j ACCEPT\n"
                    "iptables -A OUTPUT -o " << i << " -p udp --dport 68 --sport 67 -j ACCEPT\n";
            }
        }

        stream<<"\n"
            "# Switch the current language for a moment\n"
            "GUARDDOG_BACKUP_LANG=$LANG\n"
            "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
            "LANG=en_US\n"
            "LC_ALL=en_US\n"
            "export LANG\n"
            "export LC_ALL\n"
            "# Accept broadcasts from ourself.\n"
            "IP_BCAST_PAIRS=\"`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\\\"\\\\\\\\1\\\",\\\"g\\\",$1)}\n"
            "/inet addr:.*Bcast/ {match($0,/inet addr:[[:digit:]\\\\.]+/)\n"
            "ip=substr($0,RSTART+10,RLENGTH-10)\n"
            "match($0,/Bcast:[[:digit:]\\\\.]+/)\n"
            "bcast = substr($0,RSTART+6,RLENGTH-6)\n"
            "printf \\\"%s_%s_%s\\\\n\\\",nic,ip,bcast }'`\"\n"

            "# Restore the language setting\n"
            "LANG=$GUARDDOG_BACKUP_LANG\n"
            "LC_ALL=$GUARDDOG_BACKUP_LC_ALL\n"
            "export LANG\n"
            "export LC_ALL\n"

            "for X in $IP_BCAST_PAIRS ; do\n"
            "  NIC=\"`echo \\\"$X\\\" | cut -f 1 -d _`\"\n"
            "  IP=\"`echo \\\"$X\\\" | cut -f 2 -d _`\"\n"
            "  BCAST=\"`echo \\\"$X\\\" | cut -f 3 -d _`\"\n"
            "  iptables -A INPUT -i $NIC -s $IP -d $BCAST -j ACCEPT\n"
            "done\n"
            "\n";

        // Detect and log aborted TCP connections.
        if ( logabortedtcp )
        {
            stream<<"# Detect aborted TCP connections.\n"
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -p tcp --tcp-flags RST RST -j logaborted\n";
        }

        // Allow ESTABLISHED and RELATED packets.
        stream<<"# Quickly allow anything that belongs to an already established connection.\n"
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
            "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
            "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
            "\n"
            "# Allow certain critical ICMP types\n"
            "iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT  # Dest unreachable\n"
            "iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT # Dest unreachable\n"
            "iptables -A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT &> /dev/null  # Dest unreachable\n"
            "iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT            # Time exceeded\n"
            "iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT           # Time exceeded\n"
            "iptables -A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT &> /dev/null # Time exceeded\n"
            "iptables -A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT        # Parameter Problem\n"
            "iptables -A OUTPUT -p icmp --icmp-type parameter-problem -j ACCEPT       # Parameter Problem\n"
            "iptables -A FORWARD -p icmp --icmp-type parameter-problem -j ACCEPT &> /dev/null # Parameter Problem\n"
            "\n"

            "# Switch the current language for a moment\n"
            "GUARDDOG_BACKUP_LANG=$LANG\n"
            "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
            "LANG=en_US\n"
            "LC_ALL=en_US\n"
            "export LANG\n"
            "export LC_ALL\n"

            "# Work out our local IPs.\n"

            // This is insane. The amount of escaping.
            // The gawk program to be executed looks like this:
            //
            //      /^\w/ { nic = gensub(/^(.*):.*/,"\\1","g",$1)}
            //      /inet addr:/ { match($0,/inet addr:[[:digit:]\.]+/)
            //      printf "%s_%s\n",nic,substr($0,RSTART+10,RLENGTH-10) }
            //      /Bcast/ { match($0,/Bcast:[[:digit:]\.]+/)
            //      printf "%s_%s\n",nic,substr($0,RSTART+6,RLENGTH-6) }
            //
            // Now escape to put it in quotes for the shell:
            //
            //      NIC_IP="`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\"\\\\1\",\"g\",\$1)}
            //      /inet addr:/ { match(\$0,/inet addr:[[:digit:]\\.]+/)
            //      printf \"%s_%s\\n\", nic,substr(\$0,RSTART+10,RLENGTH-10) }
            //      /Bcast/ { match(\$0,/Bcast:[[:digit:]\\.]+/)
            //      printf \"%s_%s\\n\", nic,substr(\$0,RSTART+6,RLENGTH-6) }'`"
            //
            // Now we escape it again for the C compilier.

            "NIC_IP=\"`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\\\"\\\\\\\\1\\\",\\\"g\\\",\\$1)}\n"
            "/inet addr:/ { match(\\$0,/inet addr:[[:digit:]\\\\.]+/)\n"
            "printf \\\"%s_%s\\\\n\\\",nic,substr(\\$0,RSTART+10,RLENGTH-10) }\n"
            "/Bcast/ { match(\\$0,/Bcast:[[:digit:]\\\\.]+/)\n"
            "printf \\\"%s_%s\\\\n\\\",nic,substr(\\$0,RSTART+6,RLENGTH-6) }'`\"\n"

            "# Restore the language setting\n"
            "LANG=$GUARDDOG_BACKUP_LANG\n"
            "LC_ALL=$GUARDDOG_BACKUP_LC_ALL\n"
            "export LANG\n"
            "export LC_ALL\n"

            "# Create the nicfilt chain\n"
            "iptables -N nicfilt\n"
            "GOT_LO=0\n"
            "NIC_COUNT=0\n"
            "for X in $NIC_IP ; do\n"
            "    NIC=\"`echo \\\"$X\\\" | cut -f 1 -d _`\"\n"
            "    iptables -A nicfilt -i $NIC -j RETURN\n"
            "    # We also take this opportunity to see if we only have a lo interface.\n"
            "    if [ $NIC == \"lo\" ]; then\n"
            "        GOT_LO=1\n"
            "    fi\n"
            "    let NIC_COUNT=$NIC_COUNT+1\n"
            "done\n"
            "IPS=\"`echo \\\"$NIC_IP\\\" | cut -f 2 -d _`\"\n"
            "iptables -A nicfilt -j logdrop\n"
            "# Do we have just a lo interface?\n"
            "if [ $GOT_LO -eq 1 ] && [ $NIC_COUNT -eq 1 ] ; then\n"
            "  MIN_MODE=1\n"
            "else\n"
            "  MIN_MODE=0\n"
            "fi\n"
            "# Are there *any* interfaces?\n"
            "if [ $NIC_COUNT -eq 0 ] ; then\n"
            "  MIN_MODE=1\n"
            "fi\n"
            "# If we only have a lo interface or no interfaces then we assume that DNS\n"
            "# is not going to work and just skip any iptables calls that need DNS.\n";

        // Create the filter chains.
        stream<<"\n# Create the filter chains\n";
        // 'From' zone loop
        BOOST_FOREACH( Zone & zit, zones )
        {
            // 'To' zone loop
            BOOST_FOREACH( Zone & zit2, zones )
            {
                if ( zit != zit2 )
                {
                    // Create the fitler chain for this combinatin of source and dest zone.
                    stream << "# Create chain to filter traffic going from '" << zit.getName() <<"' to '" << zit2.getName() << "'\n";
                    stream << "iptables -N " << zit.getName() << "_to_" << zit2.getName() << "\n";
                }
            }
        }

        // This PortRangeInfo object holds the info about the super tight
        // port ranges our machine now uses.
        localPRI.dynamicStart = localPortRangeStart;
        localPRI.dynamicEnd = localPortRangeEnd;

        // Now we add the rules to the filter chains.
        stream<<"# Add rules to the filter chains\n";
        // 'From' zone loop
        BOOST_FOREACH( Zone const & fromZone, zones )
        {
            // 'To' zone loop
            BOOST_FOREACH( Zone const & toZone, zones )
            {
                if ( fromZone != toZone )
                {
                    // Detect and accept permitted protocols.
                    std::vector< std::string > permitZoneProtocols = getConnectedZoneProtocols( fromZone.getName(), toZone.getName(), Zone::PERMIT );
                    stream<<"\n# Traffic from '"<< fromZone.getName() << "' to '"<< toZone.getName() << "'\n";
                    BOOST_FOREACH( std::string const & zoneProtocol, permitZoneProtocols )
                    {
                        stream << "# Allow '" << zoneProtocol <<"'\n";
                        std::vector< ProtocolNetUse > networkuses = getNetworkUse( zoneProtocol );

                        BOOST_FOREACH( ProtocolNetUse & networkuse, networkuses )
                        {
                            // If this netuse has been marked with the RELATED pragma
                            // then we don't need to output it becuase netfilter will
                            // be connection tracking it. The general state handling
                            // rule will handle this connection automatically.

                            if ( !networkuse.description.empty() )
                            {
                                stream << "# "<< networkuse.description << "\n";
                            }
                            if ( networkuse.pragma[ "guarddog" ] != "RELATED" )
                            {
                                if ( networkuse.source == ENTITY_CLIENT)
                                {
                                    expandIPTablesFilterRule( stream, fromZone.getName(), fromZone.isLocal() ? &localPRI : 0,
                                            toZone.getName(), toZone.isLocal() ? &localPRI : 0, networkuse);
                                }
                                if ( networkuse.dest == ENTITY_CLIENT)
                                {
                                    expandIPTablesFilterRule( stream, toZone.getName(), toZone.isLocal() ? &localPRI : 0,
                                            fromZone.getName(), fromZone.isLocal() ? &localPRI : 0, networkuse);
                                }
                            }
                            else
                            {
                                stream<<"#  - Handled by netfilter state tracking\n";
                            }
                        }
                    }

                    // Detect and reject protocols that have been marked for such treatment. :-)

                    std::vector< std::string > rejectZoneProtocols = getConnectedZoneProtocols( fromZone.getName(), toZone.getName(), Zone::REJECT );
                    stream<<"\n# Rejected traffic from '"<<fromZone.getName()<<"' to '"<<toZone.getName()<<"'\n";
                    BOOST_FOREACH( std::string const & zoneProtocol, rejectZoneProtocols )
                    {
                        stream << "# Reject '" << zoneProtocol << "'\n";

                        std::vector< ProtocolNetUse > networkuses = getNetworkUse( zoneProtocol );

                        BOOST_FOREACH( ProtocolNetUse & networkuse, networkuses )
                        {
                            if ( networkuse.description.length() != 0 )
                            {
                                stream<<"# "<<networkuse.description <<"\n";
                            }
                            if(networkuse.source==ENTITY_CLIENT)
                            {
                                expandIPTablesFilterRule(stream,fromZone.getName(),fromZone.isLocal() ? &localPRI : 0, toZone.getName(), toZone.isLocal() ? &localPRI : 0,networkuse,false,logreject);
                            }
                            if(networkuse.dest==ENTITY_CLIENT)
                            {
                                expandIPTablesFilterRule(stream,toZone.getName(),toZone.isLocal() ? &localPRI : 0, fromZone.getName(), fromZone.isLocal() ? &localPRI : 0,networkuse,false,logreject);
                            }
                        }
                    }
                }
            }
        }

        // Place DENY and log rules at the end of our filter chains
        stream<<"\n" "# Place DROP and log rules at the end of our filter chains.\n";
        // 'From' zone loop
        BOOST_FOREACH( Zone const & fromZone, zones )
        {
            // 'To' zone loop
            BOOST_FOREACH( Zone const & toZone, zones )
            {
                if ( fromZone != toZone )
                {
                    // Finally, the DENY and LOG packet rule to finish things off.
                    stream<<"# Failing all the rules above, we log and DROP the packet.\n"
                        "iptables -A " << fromZone.getName() << "_to_" << toZone.getName() << " -j logdrop\n";
                }
            }
        }

        // Temporarily enable DNS lookups
        stream<<"\n"
            "# Add some temp DNS accept rules to the input and output chains.\n"
            "# This is so that we can pass domain names to ipchains and have iptables be\n"
            "# able to look it up without being blocked by our half-complete firewall.\n"
            "if [ $MIN_MODE -eq 0 ] ; then\n"
            "  iptables -A OUTPUT -p tcp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
            "  iptables -A INPUT -p tcp ! --syn --sport 53:53 --dport 0:65535 -j ACCEPT\n"
            "  iptables -A OUTPUT -p udp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
            "  iptables -A INPUT -p udp --sport 53:53 --dport 0:65535 -j ACCEPT\n"
            "fi\n";

        // Create the split chains.

        BOOST_FOREACH( Zone const & zit, zones )
        {
            stream<<"\n# Chain to split traffic coming from zone '" << zit.getName() <<"' by dest zone\n";
            stream<<"iptables -N " << zit.getName() <<"\n";

            // Fill the chain.
            // Branch for traffic going to the Local zone.
            if ( !zit.isLocal() )
            {
                stream<<"for X in $IPS ; do\n"
                    "    iptables -A "<<zit.getName() <<" -d $X -j " << zit.getName() <<"_to_Local" << "\n"
                    "done\n";
            }

            stream<<"if [ $MIN_MODE -eq 0 ] ; then\n";

            // Branch for traffic going to every other chain
            for(int mask=32; mask>=0; mask--)
            {
                BOOST_FOREACH( Zone const & zit2, zones )
                {
                    if ( zit != zit2 && !zit2.isLocal() && !zit2.isInternet())
                    {
                        BOOST_FOREACH( IPRange const & addy, zit2.getMemberMachineList() )
                        {
                            if ( addy.getMask()==(uint)mask)
                            {
                                stream<<"iptables -A " << zit.getName() <<" -d "<<addy.getAddress()<<" -j " << zit.getName() << "_to_" << zit2.getName() <<"\n";
                            }
                        }
                    }
                }
            }
            stream<<"    true # make sure this if [] has at least something in it.\n"
                "fi\n";

            // Add "catch all" rules for internet packets
            if ( !zit.isInternet() )
            {  // Except for the chain that handles traffic coming from the internet.
                stream<<"iptables -A " << zit.getName() <<" -j " << zit.getName() << "_to_Internet" <<"\n";
            }
            else
            {
                // We should not see traffic coming from the internet trying to go directly back
                // out to the internet. That's weird, and worth logging.
                stream<<"iptables -A "<< zit.getName() << " -j logdrop\n";
            }
        }

        // Create and fill the scrfilt chain.
        stream<<"# Create the srcfilt chain\n"
            "iptables -N srcfilt\n";
        stream<<"if [ $MIN_MODE -eq 0 ] ; then\n";
        for(int mask=32; mask>=0; mask--)
        {
            BOOST_FOREACH( Zone const & zit2, zones )
            {
                if ( !zit2.isLocal() && !zit2.isInternet())
                {
                    BOOST_FOREACH( IPRange const & addy, zit2.getMemberMachineList() )
                    {
                        if(addy.getMask() == (uint)mask)
                        {
                            stream<<"iptables -A srcfilt -s " << addy.getAddress()<<" -j "<<zit2.getName()<<"\n";
                        }
                    }
                }
            }
        }

        stream<<"    true # make sure this if [] has at least something in it.\n"
            "fi\n";

        stream<<"# Assume internet default rule\n"
            "iptables -A srcfilt -j Internet\n"
            "\n";

        // Remove the temp DNS accept rules.
        stream<<"if [ $MIN_MODE -eq 0 ] ; then\n"
            "  # Remove the temp DNS accept rules\n"
            "  iptables -D OUTPUT -p tcp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
            "  iptables -D INPUT -p tcp ! --syn --sport 53:53 --dport 0:65535 -j ACCEPT\n"
            "  iptables -D OUTPUT -p udp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
            "  iptables -D INPUT -p udp --sport 53:53 --dport 0:65535 -j ACCEPT\n"
            "fi\n"
            "\n"
            "# The output chain is very simple. We direct everything to the\n"
            "# 'source is local' split chain.\n"
            "iptables -A OUTPUT -j Local\n"
            "\n"
            "iptables -A INPUT -j nicfilt\n"
            "iptables -A INPUT -j srcfilt\n"
            "\n"
            "# All traffic on the forward chains goes to the srcfilt chain.\n"
            "iptables -A FORWARD -j srcfilt &> /dev/null\n"
            "\n"
            "logger -p auth.info -t guarddog Finished configuring firewall\n"
            "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Finished.")<<"\"\n";

    }

    ///////////////////////////////////////////////////////////////////////////
    //
    // permit==true && log==true is not supported.
    //
    void expandIPTablesFilterRule( std::ostream & stream, std::string const & fromzone, PortRangeInfo * fromzonePRI, std::string const & tozone, PortRangeInfo *tozonePRI,
            ProtocolNetUse const & netuse, bool permit = true, bool log = false)
    {
        const char *icmpname;
        ProtocolNetUseDetail const & source = netuse.sourcedetail;
        ProtocolNetUseDetail const & dest = netuse.destdetail;
        switch(netuse.type)
        {
            case IPPROTO_TCP:
                stream<<"iptables -A "<<fromzone<<"_to_"<<tozone<<" -p tcp"
                    " --sport "<<(source.getStart(fromzonePRI))<<":"<<(source.getEnd(fromzonePRI))<<
                    " --dport "<<(dest.getStart(tozonePRI))<<":"<<(dest.getEnd(tozonePRI))<<
                    " -m state --state NEW";
                if(permit)
                {
                    // Permitted
                    stream<<" -j ACCEPT\n";
                }
                else
                {
                    // Not permitted.
                    if(log)
                    {
                        stream<<" -j logreject\n";
                    }
                    else
                    {
                        stream<<" -j REJECT --reject-with tcp-reset\n";
                    }
                }
                break;

            case IPPROTO_UDP:
                stream<<"iptables -A "<<fromzone<<"_to_"<<tozone<<" -p udp"
                    " --sport "<<(source.getStart(fromzonePRI))<<":"<<(source.getEnd(fromzonePRI))<<
                    " --dport "<<(dest.getStart(tozonePRI))<<":"<<(dest.getEnd(tozonePRI));
                if(permit)
                {
                    // Permitted.
                    stream<<" -j ACCEPT\n";
                }
                else
                {
                    // Not permitted.
                    if(log)
                    {
                        stream<<" -j logreject\n";
                    }
                    else
                    {
                        stream<<" -j REJECT --reject-with icmp-port-unreachable\n";
                    }
                }
                break;

            case IPPROTO_ICMP:
                // Map the type/code into a name that iptables can understand.
                // Actuall this isn't strictly neccessary, but it does make the
                // generated much easier for people to read and audit.
                switch(source.getType())
                {
                    case 0:
                        icmpname = "echo-reply";
                        break;
                    case 3:
                        icmpname = "destination-unreachable";
                        switch(source.getCode())
                        {
                            case 0: icmpname = "network-unreachable"; break;
                            case 1: icmpname = "host-unreachable"; break;
                            case 2: icmpname = "protocol-unreachable"; break;
                            case 3: icmpname = "port-unreachable"; break;
                            case 4: icmpname = "fragmentation-needed"; break;
                            case 5: icmpname = "source-route-failed"; break;
                            case 6: icmpname = "network-unknown"; break;
                            case 7: icmpname = "host-unknown"; break;
                            case 9: icmpname = "network-prohibited"; break;
                            case 10: icmpname = "host-prohibited"; break;
                            case 11: icmpname = "TOS-network-unreachable"; break;
                            case 12: icmpname = "TOS-host-unreachable"; break;
                            case 13: icmpname = "communication-prohibited"; break;
                            case 14: icmpname = "host-precedence-violation"; break;
                            case 15: icmpname = "precedence-cutoff"; break;
                            default: break;
                        }
                        break;
                    case 4:
                        icmpname = "source-quench";
                        break;
                    case 5:
                        icmpname = "redirect";
                        switch(source.getCode())
                        {
                            case 0: icmpname = "network-redirect"; break;
                            case 1: icmpname = "host-redirect"; break;
                            case 2: icmpname = "TOS-network-redirect"; break;
                            case 3: icmpname = "TOS-host-redirect"; break;
                            default: break;
                        }
                        break;
                    case 8:
                        icmpname = "echo-request";
                        break;
                    case 9:
                        icmpname = "router-advertisement";
                        break;
                    case 10:
                        icmpname = "router-solicitation";
                        break;
                    case 11:
                        icmpname = "time-exceeded";
                        switch(source.getCode())
                        {
                            case 0: icmpname = "ttl-zero-during-transit"; break;
                            case 1: icmpname = "ttl-zero-during-reassembly"; break;
                            default: break;
                        }
                        break;
                    case 12:
                        icmpname = "parameter-problem";
                        switch(source.getCode())
                        {
                            case 0: icmpname = "ip-header-bad"; break;
                            case 1: icmpname = "required-option-missing"; break;
                            default: break;
                        }
                        break;
                    case 13:
                        icmpname = "timestamp-request";
                        break;
                    case 14:
                        icmpname = "timestamp-reply";
                        break;
                    case 17:
                        icmpname = "address-mask-request";
                        break;
                    case 18:
                        icmpname = "address-mask-reply";
                        break;
                    default:
                        icmpname = 0;
                        break;
                }

                stream<<"iptables -A "<<fromzone<<"_to_"<<tozone<<" -p icmp --icmp-type ";
                if(icmpname!=0)
                    stream<<(icmpname);
                else
                {
                    stream<<(source.getType());
                    if(source.getCode()!=-1)
                        stream<<"/"<<(source.getCode());
                }

                if(permit)                      // Permitted.
                    stream<<" -j ACCEPT\n";
                else                            // Not permitted.
                    if(log)
                        stream<<" -j logreject\n";
                    else
                        stream<<" -j DROP\n";   // We can't REJECT icmp really. But
                                                // we can't just ACCEPT it either.
                break;

            default:                            // Every other protocol.
                if(permit)
                    stream<<"iptables -A "<<fromzone<<"_to_"<<tozone<<
                        " -p "<<netuse.getType()<<
                        " -j ACCEPT\n";
                    // Unlike the ipchains code, we don't need to check for
                    // bidirectionness. We can just rely on connection tracking
                    // to handle that.
                    //TODO shouldn't we handle dropped, or logged?
                break;
        }
    }

//this needs to be public
public:
    /*!
    **  \brief  Read in firewall from stream and initialize firewall state
    **
    **  \todo the whole errorstring, parsing, etc need to be redone
    */

    void readFirewall( std::string const & filename )
    {
        std::ifstream stream( filename.c_str() );
        std::string s;
        int state;
#define READSTATE_FIRSTLINE 0
#define READSTATE_SECONDLINE 1
#define READSTATE_COPPERPLATE   2
#define READSTATE_DESCRIPTION   3
#define READSTATE_CONFIG    4
#define READSTATE_ZONECONFIG    5
#define READSTATE_USERDEFINEDPROTOCOL 6
#define READSTATE_PROTOCOLCONFIG    7
        //    bool ok;
        uint udpid;
        uchar udptype;
        uint udpstartport;
        uint udpendport;
        bool udpbidirectional;
        std::string parameterlist[] = {
            "# LOCALPORTRANGESTART=",
            "# LOCALPORTRANGEEND=",
            "# DISABLED=",
            "# LOGREJECT=",
            "# LOGDROP=",
            "# LOGABORTEDTCP=",
            "# LOGIPOPTIONS=",
            "# LOGTCPOPTIONS=",
            "# LOGTCPSEQUENCE=",
            "# LOGLEVEL=",
            "# LOGRATELIMIT=",
            "# LOGRATE=",
            "# LOGRATEUNIT=",
            "# LOGRATEBURST=",
            "# LOGWARNLIMIT=",
            "# LOGWARNRATE=",
            "# LOGWARNRATEUNIT=",
            "# DHCPC=",
            "# DHCPCINTERFACENAME=",
            "# DHCPD=",
            "# DHCPDINTERFACENAME=",
            "# ALLOWTCPTIMESTAMPS=",
        };
        uint i;
        std::string rightpart;
        bool addcr;

        state = READSTATE_FIRSTLINE;

        std::getline( stream, s );
        if ( s.empty() ) throw std::string( "Error reading first line" );

        state = READSTATE_SECONDLINE;

        std::getline( stream, s );
        if(s.empty()) throw std::string( "Error reading second line" );

        if ( s=="## [GuardDog]" )
        {
            throw std::string( "Sorry, old Guarddog firewall files can not be read." );
        }
        else if ( s != "# [GuardPuppy]" && s != "# [Guarddog2]" )
        {
            throw std::string("Error reading firewall file. This does not appear to be a Guarddog or GuardPuppy firewall file.");
        }

        // Read past the boring human readable copperplate stuff.
        state = READSTATE_COPPERPLATE;
        while ( true )
        {
            std::getline( stream, s );
            if ( s.empty()) throw std::string("Error reading file. (Before [Config] section.)");
            if ( s == "# [Config]" )
            {   // Config is starting, goodie, lets break this.
                state = READSTATE_CONFIG;
                break;
            }
            if ( s == "# [Description]" )
            {
                state = READSTATE_DESCRIPTION;
                break;
            }
        }

        // Read the firewall description.
        description = "";
        addcr = false;
        if ( state == READSTATE_DESCRIPTION )
        {
            while ( true )
            {
                std::getline( stream, s );
                if ( s.empty() ) std::string("Error reading file. ([Config] section.)");
                if ( s == "# [Config]" )
                {
                    state = READSTATE_CONFIG;
                    break;
                }
                if ( addcr == true )
                {
                    description.append("\n");
                }
                addcr = true;
                description += (s.substr(3));
            }
        }

        state = READSTATE_CONFIG;
        while ( true )
        {
            std::getline( stream, s );
            if ( s.empty()) std::string("Error reading firewall. (In the Zone config).");
            if ( s.substr(0,3) == ("# [") )
            {
                break;  // We've got to the end of this part of the show.
            }
            // Try to identify the line we are looking at.
            for(i=0; i < 22 /*parameterlist.size()*/; i++)
            {
                if ( s.substr(0, parameterlist[i].size() ) == (parameterlist[i]))
                {
                    break;
                }
            }
            if ( i < 22 /*parameterlist.size()*/ )
            {
                rightpart = s.substr(parameterlist[i].size());
                switch(i)
                {
                    case 0:     // # LOCALPORTRANGESTART=
                        localPortRangeStart = boost::lexical_cast<uint>( rightpart ); //.toUInt(&ok);
                        if(localPortRangeStart<1024)
                        {
                            throw std::string ("Value in LOCALPORTRANGESTART section was less then 1024.");
                        }
                        break;
                    case 1:     // # LOCALPORTRANGEEND=
                        localPortRangeEnd = boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                        if(localPortRangeEnd>65535) {
                            throw std::string("Value in LOCALPORTRANGEEND is greater than 65535.");
                        }
                        break;
                    case 2:     // # DISABLED=
                        disabled = rightpart=="1";
                        break;
                    case 3:     // # LOGREJECT=
                        logreject = rightpart=="1";
                        break;
                    case 4:     // # LOGDROP=
                        logdrop = rightpart=="1";
                        break;
                    case 5:     // # LOGABORTEDTCP=
                        logabortedtcp = rightpart=="1";
                        break;
                    case 6:     // # LOGIPOPTIONS=
                        logipoptions = rightpart=="1";
                        break;
                    case 7:     // # LOGTCPOPTIONS=
                        logtcpoptions = rightpart=="1";
                        break;
                    case 8:     // # LOGTCPSEQUENCE=
                        logtcpsequence = rightpart=="1";
                        break;
                    case 9:     // # LOGLEVEL=",
                        loglevel = boost::lexical_cast<uint>( rightpart );
                        if(loglevel>7)
                        {
                            throw std::string("Error, the value in the LOGLEVEL section is too big.");
                        }
                        break;
                    case 10:     // # LOGRATELIMIT=
                        logratelimit = rightpart=="1";
                        break;
                    case 11:    // # LOGRATE=
                        lograte = boost::lexical_cast<uint>( rightpart );
                        if(lograte>65535)
                        {
                            throw std::string("Error, the value in the LOGRATE section is too big (>65535).");
                        }
                        break;
                    case 12:    // # LOGRATEUNIT=
                        lograteunit = (LogRateUnit)boost::lexical_cast<uint>( rightpart );
                        if(lograteunit>3)
                        {
                            throw std::string("Error the value in the LOGRATEUNIT section is out of range.");
                        }
                        break;
                    case 13:    // # LOGRATEBURST=
                        lograteburst = boost::lexical_cast<uint>( rightpart );
                        if(lograteburst > 65535) {
                            throw std::string("Error, the value in the LOGRATEBURST section is too big.");
                        }
                        break;
                    case 14:    // # LOGWARNLIMIT=
                        logwarnlimit = rightpart=="1";
                        break;
                    case 15:    // # LOGWARNRATE=
                        logwarnrate = boost::lexical_cast<uint>( rightpart );
                        if(logwarnrate > 65535)
                        {
                            throw std::string("Error, the value in the LOGWARNRATE section is too big (>65535).");
                        }
                        break;
                    case 16:    // # LOGWARNRATEUNIT=
                        logwarnrateunit = (LogRateUnit)boost::lexical_cast<uint>( rightpart );
                        if(logwarnrateunit>3)
                        {
                            throw std::string("Error the value in the LOGWARNRATEUNIT section is out of range.");
                        }
                        break;
                    case 17:    // # DHCPC=
                        dhcpcenabled = rightpart=="1";
                        break;
                    case 18:    // # DHCPCINTERFACENAME=
                        dhcpcinterfacename = rightpart;
                        break;
                    case 19:    // # DHCPD=
                        dhcpdenabled = rightpart=="1";
                        break;
                    case 20:    // # DHCPDINTERFACENAME=
                        dhcpdinterfacename = rightpart;
                        break;
                    case 21:    // # ALLOWTCPTIMESTAMPS=
                        allowtcptimestamps = rightpart=="1";
                        break;

                    default:
                        // Should we complain?
                        break;
                }
            }
        }

        // Sanity check these values.
        if ( localPortRangeEnd < localPortRangeStart)
        {
            throw std::string("Value for LOCALPORTRANGEEND is less than the one in LOCALPORTRANGESTART");
        }

        state = READSTATE_ZONECONFIG;

        // Parse a Zone record.
        while( s =="# [Zone]")
        {
            Zone newzone(Zone::UserZone);

            // Parse the Zone name.
            std::getline( stream, s );
            if ( s.empty() || s.substr( 0, 7) != ("# NAME="))
            {
                throw std::string("Error parsing firewall [Zone] section. Expected '# NAME='");
            }
            newzone.setName( s.substr(7) );

            // Parse the Zone comment.
            std::getline( stream, s );
            if(s.empty() || s.substr(0,10) != ("# COMMENT="))
            {
                throw std::string("Error parsing firewall [Zone] section. Expected '# COMMENT='");
            }
            newzone.setComment( s.substr(10) );

            // Parse the Zone addresses.
            while(true)
            {
                std::getline( stream, s );
                if(s.empty() || s.substr(0,10) == ("# ADDRESS="))
                {
                    newzone.addMemberMachine(IPRange(s.substr(10)));
                }
                else
                {
                    zones.push_back(newzone);
                    break;
                }
            }
        }

        // Read in any user defined protocols.
        state = READSTATE_USERDEFINEDPROTOCOL;
        while(s=="# [UserDefinedProtocol]")
        {
            // Snarf the ID.
            std::getline( stream, s );
            if(s.empty() || s.substr(0,5) != ("# ID="))
            {
                throw std::string("Error parsing firewall [UserDefinedProtocol] section. Expected '# ID='");
            }
            udpid = boost::lexical_cast<uint>( s.substr(5));

            // Snarf the NAME
            std::getline( stream, s );
            if(s.empty() || s.substr(0,7) != ("# NAME="))
            {
                throw std::string("Error parsing firewall [UserDefinedProtocol] section. Expected '# NAME='");
            }
            std::string tmpstring = s.substr(7);
            ProtocolEntry * ent;
            try { ent = &pdb.lookup(tmpstring); }
            catch(...)
            {
                ProtocolEntry t(tmpstring);
                pdb.addProtocolEntry(t);
                ent = &pdb.lookup(tmpstring);
                ent->Classification = "User Defined";
                ent->longname = tmpstring; //for udp the name and long name are the same
            }

            std::getline( stream, s );
            do
            {
                // Snarf the protocol type.
                if(s.empty() || s=="# TYPE=TCP")
                {
                    udptype = IPPROTO_TCP;
                }
                else
                {
                    if(s=="# TYPE=UDP")
                    {
                        udptype = IPPROTO_UDP;
                    }
                    else
                    {// Add support for other types of sockets (like RAW)?
                        throw std::string("Error parsing firewall [UserDefinedProtocol] section. Expected '# TYPE=TCP' or '# TYPE=UDP'");
                    }
                }

                // Snarf the PORT now.
                std::getline( stream, s );
                if(s.empty() || s.substr(0,7) != ("# PORT="))
                {
                    throw std::string("Error parsing firewall [UserDefinedProtocol] section. Expected '# PORT='");
                }

                // # PORT=xxx:yyy
                // or for compatebility
                // # PORT=xxx
                //
                // if the colon is missing, it's file from an older version
                if (s.find(":") == std::string::npos)
                    udpstartport = udpendport = boost::lexical_cast<uint>(s.substr(7));
                else
                {
                    udpstartport = boost::lexical_cast<uint>(s.substr(7, s.find(":")-7));
                    udpendport = boost::lexical_cast<uint>(s.substr(s.find(":")+1));
                }

                // Bidirectional or not?
                std::getline( stream, s );
                if(s.empty() || s=="# BIDIRECTIONAL=0")
                    udpbidirectional = false;
                else
                {
                    if ( s=="# BIDIRECTIONAL=1" )
                        udpbidirectional = true;
                    else
                        throw std::string("Error parsing firewall [UserDefinedProtocol] section. Expected '# BIDIRECTIONAL=0' or '# BIDIRECTIONAL=1'");
                }
                ProtocolNetUse t;
                t.addDest(ProtocolNetUseDetail(PORTRANGE_RANGE, udpstartport, udpendport));
                t.setType(udptype);
                t.setBidirectional(udpbidirectional);
                ent->addNetwork(t);
                std::getline( stream, s );
            }while(s.empty() || s.substr(0, 7) == "# TYPE=" );
        }

        state = READSTATE_PROTOCOLCONFIG;

        std::vector<Zone>::const_iterator       toZone = zones.begin();
        std::vector<Zone>::iterator fromZone  = zones.begin();
        // Parse the protocol info.
        while ( true )
        {
            //  If I follow this code corectly, the name after [ToZone] should match toZone.getName()
            if ( s.substr(0,10) == ("# [ToZone]") || s.substr( 0, 14 ) == "# [ServerZone]" )
            {
                fromZone  = zones.begin();

                std::getline( stream, s );
                if ( s.empty() ) throw std::string( "Empty string read2" );

                while ( true )
                {
                    if ( fromZone  == toZone )
                    {
                        ++fromZone ;
                    }
                    if ( s.substr(0,12) == ("# [FromZone]") || s.substr(0,14) == ("# [ClientZone]" ) )
                    {
                        //  If I follow this code corectly, the name after [FromZone] should match fromZone .getName()
                        std::getline( stream, s );
                        if(s.empty()) throw std::string( "Empty string read3" );

                        if ( s.substr(0,13) == ("# CONNECTED=1") )
                        {
                            updateZoneConnection( fromZone ->getName(), toZone->getName(), true );

                            while(true)
                            {
                                std::getline( stream, s );
                                if ( s.empty() ) throw std::string( "Empty string read4" );

                                if ( s.substr(0,11) == ("# PROTOCOL=") )
                                {
                                    if(s.substr(11,11) == "userdefined" )
                                    {
                                        std::cerr << "Attempt to import GuardDog file. Zone connection failed for "<< s.substr(11) << std::endl;
                                    }
                                    else
                                    {
                                        try
                                        {
                                            ProtocolEntry & pe = pdb.lookup(s.substr(11));
                                            fromZone->setProtocolState( *toZone, pe, Zone::PERMIT );
                                        }
                                        catch ( ... )
                                        {
                                            std::cout << "Shouldn't see this anymore..." << std::endl;
                                        }
                                    }
                                }
                                else
                                {
                                    if ( s.substr(0,9) == ("# REJECT=") )
                                    {
                                        if(s.substr(9,11) == "userdefined" )
                                        {
                                            std::cerr << "Attempt to import GuardDog file. Zone connection failed for "<< s.substr(9) << std::endl;
                                        }
                                        else
                                        {
                                            try
                                            {
                                                ProtocolEntry & pe = pdb.lookup(s.substr(9));
                                                fromZone->setProtocolState( *toZone, pe, Zone::REJECT );
                                            }
                                            catch ( ... )
                                            {
                                                std::cout << "Shouldn't see this anymore..." << std::endl;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                        else
                        {
                            // This zone is disconnected.
                            if ( s.substr(0,13) != ("# CONNECTED=0"))
                            {
                                throw std::string("Error parsing firewall [ToZone] section. Expected '# CONNECTED=0' or '# CONNECTED=1'");
                            }
                            fromZone->disconnect( toZone->getName() );
                            std::getline( stream, s );
                            if ( s.empty() ) throw std::string( "Empty string read5" );
                        }
                        ++fromZone ;  // Take us to the next client zone in anticipation.
                    }
                    else
                    {
                        ++toZone;
                        break;
                    }
                }
            }
            else if(s.substr(0,7) == ("# [End]"))
            {
                break;
            }
            else
            {
                throw std::string( "Empty string read6" );
            }
        }
    }
//i need this also public
    /*!
    **  \brief Set firewall to known "good" defaults
    */
    void factoryDefaults()
    {
        zones.clear();
        disabled = false;
        logreject = true;

        // Default Internet Zone.
        Zone inetzone(Zone::InternetZone);
        inetzone.setName( "Internet" );
        inetzone.setComment("Internet/Default Zone [built in]");
        zones.push_back(inetzone);

        // Default Local Machine Zone.
        Zone localzone(Zone::LocalZone);
        localzone.setName( "Local" );
        localzone.setComment("Local Machine zone [built in]");
        zones.push_back(localzone);

        updateZoneConnection( inetzone.getName(), localzone.getName(), true );
        updateZoneConnection( localzone.getName(), inetzone.getName(), true );

        localPortRangeStart = 1024;
        localPortRangeEnd = 5999;

        logdrop = true;
        logreject = true;
        logabortedtcp = true;
        logipoptions = true;
        logtcpoptions = true;
        logtcpsequence = true;
        loglevel = 4;
        logratelimit = true;
        lograte = 1;
        lograteunit = SECOND;
        lograteburst = 10;
        logwarnlimit = true;
        logwarnrate = 2;
        logwarnrateunit = MINUTE;
        dhcpcenabled = false;
        dhcpcinterfacename = "eth0";
        dhcpdenabled = false;
        dhcpdinterfacename = "eth0";
        allowtcptimestamps = false;

        description = "";
    }
private:
    /*!
    **  \brief  Execute the filename as a shell command
    */
    void runFirewall( std::string const & filename )
    {
        std::string command;

        command = filename;
        // From the command line this construct looks something like:

        int rv = system( command.c_str() );
        if ( rv == -1 ) throw std::string( "System command failed" );
    }


    /*!
    **  \brief This simples removes any firewall that maybe current in force on the system.
    */
    void resetSystemFirewall()
    {
        std::string command;

        command = "FILTERSYS=0\n"
            "if [ -e /sbin/iptables ]; then\n"
            "  FILTERSYS=2\n"
            "fi;\n"
            "if [ $FILTERSYS -eq 0 ]; then\n"
            "  /usr/bin/logger -p auth.info -t guarddog \"ERROR Can't determine the firewall command! (Is iptables installed?)\"\n"
            "fi;\n"
            "if [ $FILTERSYS -eq 2 ]; then\n"
            "/sbin/iptables -P OUTPUT ACCEPT\n"
            "/sbin/iptables -P INPUT ACCEPT\n"
            "/sbin/iptables -P FORWARD ACCEPT\n"
            "/sbin/iptables -F FORWARD\n"
            "/sbin/iptables -F INPUT\n"
            "/sbin/iptables -F OUTPUT\n"
            "fi;\n"
            "read -p \"Press return to continue\"\n";

        int rv = system( command.c_str() );
        if ( rv == -1 ) throw std::string( "system command returned error" );
    }

public:
//TODO make these safe to call with bad strings.
    std::string getName(std::string s) const
    {
        return pdb.lookup(s).getName();
    }
    std::vector<uchar> getTypes(std::string s) const
    {
        return pdb.lookup(s).getTypes();
    }

    std::vector<uint> getStartPorts(std::string s) const
    {
        return pdb.lookup(s).getStartPorts();
    }
    void setStartPort(std::string s, uint i, int j)
    {
        pdb.lookup(s).setStartPort(i, j);
    }
    std::vector<uint> getEndPorts(std::string s) const
    {
        return pdb.lookup(s).getEndPorts();
    }
    void setEndPort(std::string s, uint i, int j)
    {
        pdb.lookup(s).setEndPort(i, j);
    }
    std::vector<bool> getBidirectionals(std::string s) const
    {
        return pdb.lookup(s).getBidirectionals();
    }
    void setBidirectional(std::string s, bool on, int j)
    {
        pdb.lookup(s).setBidirectional(on, j);
    }

    template <class T>
    void ApplyToDB(T & func)
    {
        pdb.ApplyToDB(func);
    }

    template<class T>
    void ApplyToNthInClass(T & func, int i, std::string c)
    {
        pdb.ApplyToNthInClass(func, i, c);
    }
};

