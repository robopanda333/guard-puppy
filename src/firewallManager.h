
#pragma once
#include <netinet/in.h>
#include <vector>
#include <string>
#include <iostream>
#include <boost/foreach.hpp>

#include <QXmlDefaultHandler>

#include "protocoldb.h"

//!Arbiter between the the client side and all the data.
/*!
 * Where the magic happens.
 * Contains all the access functions that any front would need to get and modify data.
 * Has the XML parser to populate the ProtocolDB.
 * Has the Config file parser to populate the ZoneDB, and add new firewalls.
 * Has direct access to the ProtocolDB, and ZoneDB.
 * Mediates any change in one DB, so that information in others are updated as well.
 *
 */
class FirewallManager
{
    //!The Protocol Database
    ProtocolDB pdb;

    //!The Zone Database
    //ZoneDB & zdb; //Add this class into here when it is ready

    //!The list of firewalls
    //std::vector<Firewall> fw;
public:
//accessor functions: Protocols

//accessor functions: Zones

};

//!Helper class for parsing the XML and populating the Protocol DB
class ProtocolXMLParser: public QXmlDefaultHandler
{
    //! States used for Parsing the XML file
    enum ParserState
    {
        PROTOCOL_STATE_UNKNOWN,
        PROTOCOL_STATE_OUTSIDE = 1,
        PROTOCOL_STATE_PROTOCOLDB,
        PROTOCOL_STATE_ENTRY,
        PROTOCOL_STATE_ENTRY_PRAGMA,
        PROTOCOL_STATE_LONGNAME,
        PROTOCOL_STATE_DESCRIPTION,
        PROTOCOL_STATE_NETWORK,
        PROTOCOL_STATE_SECURITY,
        PROTOCOL_STATE_CLASSIFICATION,
        PROTOCOL_STATE_FINISHED,
        PROTOCOL_STATE_TCP_SOURCE=16,           //0000 10
        PROTOCOL_STATE_UDP_SOURCE=17,           //0001 11
        PROTOCOL_STATE_TCP_SOURCE_PORT=18,      //0010 12
        PROTOCOL_STATE_UDP_SOURCE_PORT=19,      //0011 13
        PROTOCOL_STATE_TCP_SOURCE_PORTRANGE=20, //0100 14
        PROTOCOL_STATE_UDP_SOURCE_PORTRANGE=21, //0101 15
        PROTOCOL_STATE_TCP_DEST=24,             //1000 18
        PROTOCOL_STATE_UDP_DEST=25,             //1001 19
        PROTOCOL_STATE_TCP_DEST_PORT=26,        //1010 1A
        PROTOCOL_STATE_UDP_DEST_PORT=27,        //1011 1B
        PROTOCOL_STATE_TCP_DEST_PORTRANGE=28,   //1100 1C
        PROTOCOL_STATE_UDP_DEST_PORTRANGE=29,   //1101 1D
        PROTOCOL_STATE_TCP,
        PROTOCOL_STATE_UDP,
        PROTOCOL_STATE_ICMP,
        PROTOCOL_STATE_IP,
        PROTOCOL_STATE_TCP_PRAGMA,
        PROTOCOL_STATE_UDP_PRAGMA,
        PROTOCOL_STATE_ICMP_PRAGMA,
        PROTOCOL_STATE_IP_PRAGMA,
        PROTOCOL_STATE_TCP_DESCRIPTION,
        PROTOCOL_STATE_UDP_DESCRIPTION,
        PROTOCOL_STATE_ICMP_DESCRIPTION,
        PROTOCOL_STATE_IP_DESCRIPTION,
        PROTOCOL_STATE_ICMP_TYPE
    };
    //! In the case of Error check errorstate for one of these values.
    enum ErrorState
    {
        PROTOCOL_ERROR_NOERROR,
        PROTOCOL_ERROR_OPEN_ERROR,
        PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_TCP_SRCDEST_UNKNOWN,
        PROTOCOL_ERROR_UDP_SRCDEST_UNKNOWN,
        PROTOCOL_ERROR_ICMP_SRCDEST_UNKNOWN,
        PROTOCOL_ERROR_IP_SRCDEST_UNKNOWN,
        PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND,
        PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN,
        PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN,
        PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT,
        PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN
    };

    ProtocolDB & pdb;
    uint unknowndepth; //<!used to skip over unknown tags, apparently
    std::vector<std::string> parseerror;
    std::vector<std::string> languagelist;
    bool loaddescription;
    bool loadlongname;
    ParserState parsestate;
    ErrorState errorstate;
    //stateful variables
    ProtocolEntry currententry;
    ProtocolEntry::ProtocolNet currentnetuse;
    ProtocolEntry::PortRange currentnetusedetail;
    std::string lastPragmaName;

//start element Helper case functions
    bool caseProtocolStateOutside( QString const & localName );
    bool caseProtocolStateProtocolDB( QString const & localName, QXmlAttributes const & atts );
    bool caseProtocolStateEntry( QString const & localName, QXmlAttributes const & atts );
    bool caseProtocolStateEntryLongName( QXmlAttributes const & atts );
    bool caseProtocolStateEntryDescription( QXmlAttributes const & atts );
    bool caseProtocolStateEntryClassification( QXmlAttributes const & atts );
    bool caseProtocolStateEntryNetwork();
    bool caseProtocolStateEntrySecurity( QXmlAttributes const & atts );
    bool caseProtocolStateEntryPragma( QXmlAttributes const & atts );
    bool caseProtocolStateNetwork( QString const & localName, QXmlAttributes const & atts );
    bool caseProtocolStateNetworkHandleAttribute( QXmlAttributes const & atts, uint8_t type,
             ProtocolEntry::ProtocolNet * cur,
             void (ProtocolEntry::ProtocolNet::* )(ProtocolEntry::ProtocolNet::Role),
             std::string sym);
    bool caseProtocolStateTCP( QString const & localName, QXmlAttributes const & atts );
    bool caseProtocolStateUDP( QString const & localName, QXmlAttributes const & atts );
    bool caseProtocolStateICMP( QString const & localName, QXmlAttributes const & atts );
    bool caseProtocolStateIP( QString const & localName, QXmlAttributes const & atts );
    void caseProtocolStateDescriptionLanguage(QXmlAttributes const & atts);
    bool caseProtocolStateSrcDest( QString const & localName, QXmlAttributes const & atts );
    bool caseProtocolStateSrcDestPort( QXmlAttributes const & atts );
    bool caseProtocolStateSrcDestRange( QXmlAttributes const & atts );

public:
    //!Constructs the parser and automaticly parses and populates the passed in Database
    ProtocolXMLParser( std::string const & filename, ProtocolDB _pdb );
    ~ProtocolXMLParser() {}

    bool loadDB(std::string const & filename);
    bool startDocument();

    bool startElement(QString const &, QString const &, QString const &, QXmlAttributes const &);
    bool endElement(QString const &, QString const &, QString const &);
    bool characters( QString const & ch );

    //maybe these should be a static member of ProtocolEntry?
    ProtocolEntry::Score getScore( std::string const & s )
    {
        if( s == "low" )
            return ProtocolEntry::LOW;
        else if (s == "medium" )
            return ProtocolEntry::MEDIUM;
        else if (s == "high" )
            return ProtocolEntry::HIGH;
        else
            return ProtocolEntry::UNKNOWN;
    }
    ProtocolEntry::RangeType getRangeType(std::string const & s)
    {
        if( s == "any" )
            return ProtocolEntry::ANY;
        else if( s == "privileged" )
            return ProtocolEntry::PRIVILEGED;
        else if( s == "nonprivileged" )
            return ProtocolEntry::NONPRIVILIGED;
        else if( s == "dynamic" )
            return ProtocolEntry::DYNAMIC;
        else
            return ProtocolEntry::RANGE;
    }
    uint8_t getType ( std::string const & s )
    {
        if(s == "tcp")
            return IPPROTO_TCP;
        else if(s == "udp")
            return IPPROTO_UDP;
        else if(s == "icmp")
            return IPPROTO_ICMP;
        else if(s == "icmpv6")
            return IPPROTO_ICMPV6;
        else
            return IPPROTO_IP;
    }

};

