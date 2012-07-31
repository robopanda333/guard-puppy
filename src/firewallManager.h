

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

};
//!Helper class for parsing the XML and populating the Protocol DB
class ProtocolXMLParser: public QXMLDefaultHandler
{
using std::string;
    ProtocolDB & pdb;
    uint unknowndepth; //<!used to skip over unknown tags, apparently

    //for readability we'll define the namespace
    #define protocolnamespace = "";

    std::vector<string> parseerror;
    std::vector<string> languagelist;
    bool loaddescription;
    bool loadlongname;

    //! States used for Parsing the XML file
    enum ParserState
    {
        PROTOCOL_STATE_OUTSIDE = 1,
        PROTOCOL_STATE_PROTOCOLDB,
        PROTOCOL_STATE_ENTRY,
        PROTOCOL_STATE_ENTRY_PRAGMA,
        PROTOCOL_STATE_LONGNAME,
        PROTOCOL_STATE_DESCRIPTION,
        PROTOCOL_STATE_NETWORK,
        PROTOCOL_STATE_TCP,
        PROTOCOL_STATE_UDP,
        PROTOCOL_STATE_ICMP,
        PROTOCOL_STATE_IP,
        PROTOCOL_STATE_IP_PRAGMA,
        PROTOCOL_STATE_IP_DESCRIPTION,
        PROTOCOL_STATE_ICMP_PRAGMA,
        PROTOCOL_STATE_TCP_SOURCE,
        PROTOCOL_STATE_TCP_DEST,
        PROTOCOL_STATE_TCP_PRAGMA,
        PROTOCOL_STATE_UDP_SOURCE,
        PROTOCOL_STATE_UDP_DEST,
        PROTOCOL_STATE_UDP_PRAGMA,
        PROTOCOL_STATE_TCP_DESCRIPTION,
        PROTOCOL_STATE_UDP_DESCRIPTION,
        PROTOCOL_STATE_ICMP_DESCRIPTION,
        PROTOCOL_STATE_TCP_SOURCE_PORT,
        PROTOCOL_STATE_TCP_DEST_PORT,
        PROTOCOL_STATE_UDP_SOURCE_PORT,
        PROTOCOL_STATE_UDP_DEST_PORT,
        PROTOCOL_STATE_TCP_SOURCE_PORTRANGE,
        PROTOCOL_STATE_TCP_DEST_PORTRANGE,
        PROTOCOL_STATE_UDP_SOURCE_PORTRANGE,
        PROTOCOL_STATE_UDP_DEST_PORTRANGE,
        PROTOCOL_STATE_SECURITY,
        PROTOCOL_STATE_ICMP_TYPE,
        PROTOCOL_STATE_CLASSIFICATION,

        PROTOCOL_STATE_UNKNOWN,
        PROTOCOL_STATE_FINISHED
    } parsestate;
    //! In the case of Error check errorstate for one of these values.
    enum ErrorState
    {
        PROTOCOL_ERROR_NOERROR,
        PROTOCOL_ERROR_OPEN_ERROR,
        PROTOCOL_ERROR_PARSE_ERROR,
        PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_TCP_DEST_UNKNOWN,
        PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_UDP_DEST_UNKNOWN,
        PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_ICMP_DEST_UNKNOWN,
        PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND,
        PROTOCOL_ERROR_IP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_IP_DEST_UNKNOWN,
        PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT,
        PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE,
        PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT,
        PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT,
        PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT,
        PROTOCOL_ERROR_PORTRANGE_END_LESS_START,
        PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN,
        PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN,
        PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT,
        PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT,
        PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN
    } errorstate;

public:
    //!Constructs the parser and automaticly parses and populates the passed in Database
    ProtocolXMLParser( string const & filename, ProtocolDB _pdb ): pdb(_pdb)
    {
        languageslist.push_back( "en" );//we want at least one permited language

        loadDB(filename);
    }
    ~ProtocolXMLParser()
    {}

    bool loadDB(string const & filename)
    {
        QFile xmlfile( filename.c_str() );
        if( !xmlfile.open( QIODevice::ReadOnly ) )//opens the file as readonly, and if fails
        {
            errorstate = PROTOCOL_ERROR_OPEN_ERROR;
            std::cerr << "Unable to open: " << filename << std::endl;
            return false;
        }
        QXmlInputSource source(&xmlfile);
        QXmlSimpleReader reader;
        reader.setContentHandler(this);
        reader.setErrorHandler(this);
        //parseerror.clear(); // it... like has to be empty already...
        if( !reader.parse( source ) )
        {
            std::cerr << "Failed Parsing " << filename << std::endl
                      << errorString().toStdString() << std::endl;
            xmlfile.close();
            return false;
        }
        xmlfile.close();
        return true;
    }

    bool startDocument()
    {
        parsestate = PROTOCOL_STATE_OUTSIDE;
        errorstate = PROTOCOL_ERROR_NOERROR;
        unknowndepth = 0;
        return true;
    }

    //in the past this function was a nightmare... lets see if we can help...
    bool startElement(QString const & /*namespaceURI*/, QString const & localName, Qstring const &/*qName*/, QXmlAttributes const & atts )
    {
        if(unknowndepth > 0)
            return unknowndepth++;

        switch(parsestate)
        {
            case PROTOCOL_STATE_OUTSIDE:
                return caseProtocolStateOutside(localName);
            case PROTOCOL_STATE_PROTOCOLDB:
                caseProtocolStateProtocolDB(localName, atts);
            case PROTOCOL_STATE_ENTRY:
                caseProtocolStateEntry(localName);
            case PROTOCOL_STATE_NETWORK:
                caseProtocolStateNetwork(localName);
            case PROTOCOL_STATE_TCP:
                caseProtocolStateTCP(localName);
            case PROTOCOL_STATE_UDP:
                caseProtocolStateUDP(localName);
            case PROTOCOL_STATE_ICMP:
                caseProtocolStateICMP(localName);
            case PROTOCOL_STATE_IP:
                caseProtocolStateIP(localName);
            case PROTOCOL_STATE_TCP_SOURCE: case PROTOCOL_STATE_UDP_SOURCE: case PROTOCOL_STATE_TCP_DEST: case PROTOCOL_STATE_UDP_DEST:
                caseProtocolState(localName);
            default:
                return unknowndepth++;
        }
    }
    bool endElement(QString const &/*namespaceURI*/, Qstring const &/*localName*/, QString const &/*qName*/)
    {
        if(unknowndepth>0)
        {
            unknowndepth--;
            return true;
        }
        switch(parsestate)
        {
            case PROTOCOL_STATE_PROTOCOLDB:
                return parsestate = PROTOCOL_STATE_FINISHED;
            case PROTOCOL_STATE_ENTRY:
                //addProtocolEntry( currententry );
                return parsestate = PROTOCOL_STATE_PROTOCOLDB;
            case PROTOCOL_STATE_LONGNAME: case PROTOCOL_STATE_DESCRIPTION: case PROTOCOL_STATE_SECURITY: case PROTOCOL_STATE_NETWORK: case PROTOCOL_STATE_CLASSIFICATION: case PROTOCOL_STATE_ENTRY_PRAGMA:
                return parsestate = PROTOCOL_STATE_ENTRY;
            case PROTOCOL_STATE_TCP: case PROTOCOL_STATE_UDP: case PROTOCOL_STATE_ICMP: case PROTOCOL_STATE_IP:
                //currententry.addNetwork( currentnetuse );
                return parsestate = PROTOCOL_STATE_NETWORK;
            case PROTOCOL_STATE_TCP_SOURCE: case PROTOCOL_STATE_TCP_DEST: case PROTOCOL_STATE_TCP_DESCRIPTION: case PROTOCOL_STATE_TCP_PRAGMA:
                return parsestate = PROTOCOL_STATE_TCP;
            case PROTOCOL_STATE_UDP_SOURCE: case PROTOCOL_STATE_UDP_DESCRIPTION: case PROTOCOL_STATE_UDP_PRAGMA:
                return parsestate = PROTOCOL_STATE_UDP;
            case PROTOCOL_STATE_ICMP_TYPE:
                //currentnetuse.addSource( currentnetusedetail );
                return parsestate = PROTOCOL_STATE_ICMP;
            case PROTOCOL_STATE_ICMP_DESCRIPTION: case PROTOCOL_STATE_ICMP_PRAGMA:
                return parsestate = PROTOCOL_STATE_ICMP;
            case PROTOCOL_STATE_STATE_IP_DESCRIPTION: case PROTOCOL_STATE_IP_PRAGMA:
                return parsestate = PROTOCOL_STATE_IP;
            case PROTOCOL_STATE_TCP_SOURCE_PORT: case PROTOCOL_STATE_TCP_SOURCE_PORTRANGE:
                //currentnetuse.addSource( currentnetusedetail );
                return parsestate = PROTOCOL_STATE_TCP_SOURCE;
            case PROTOCOL_STATE_TCP_DEST_PORT: case PROTOCOL_STATE_TCP_DEST_PORTRANGE:
                //currentnetuse.addDest( currentnetusedetail );
                return parsestate = PROTOCOL_STATE_TCP_DEST;
            case PROTOCOL_STATE_UDP_SOURCE_PORT: case PROTOCOL_STATE_UDP_SOURCE_PORTRANGE:
                //currentnetuse.addSource( currentnetusedetail );
                return parsestate = PROTOCOL_STATE_UDP_SOURCE;
            case PROTOCOL_STATE_UDP_DEST_PORT: case PROTOCOL_STATE_UDP_DEST_PORTRANGE:
                //currentnetuse.addDest( currentnetusedetail );
                return parsestate = PROTOCOL_STATE_UDP_DEST;
            default: return false;
        }

    }
    bool characters( QString const & ch )
        {
            if( unknowndepth )
                return true;
            switch( parsestate )
            {
                case PROTOCOL_STATE_LONGNAME:
                    if( loadlongname )
                        currententry.longname = ch.toStdString();
                    return true;
                case PROTOCOL_STATE_DESCRIPTION:
                    if( loaddescription )
                        currententry.description = ch.toStdString();
                    return true;
                case PROTOCOL_STATE_ENTRY_PRAGMA:
                    currententry.addPragmaValue( ch.toStdString() );
                    return true;
                case PROTOCOL_STATE_TCP_DESCRIPTION: case PROTOCOL_STATE_UDP_DESCRIPTION: case PROTOCOL_STATE_ICMP_DESCRIPTION:
                    if( loaddescription )
                        currentnetuse.description = ch.toStdString();
                    return true;
                case PROTOCOL_STATE_TCP_PRAGMA: case PROTOCOL_STATE_UDP_PRAGMA: case PROTOCOL_STATE_ICMP_PRAGMA:
                    currentnetuse.addPragmaValue( ch.toStdString() );
                    return true;
                default:
                    return true;
            }
        }

    //maybe this should be a static member of ProtocolEntry?
    ProtocolEntry::Score getScore(string const & s)
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
//start element case functions
    void caseProtocolStateOutside( QString const & localName )
    {
        if( localName == "protocoldb" )
            return parsestate = PROTOCOL_STATE_PROTOCOLDB;
        return unknowndepth++;
    }
    void caseProtocolStateProtocolDB( QString const & localName , QXmlAttributes const & atts )
    {
        int i;
        if( localName == "protocol" )
        {
            currententry = ProtocolEntry();
            i = atts.index( protocolnamespace, "name" );
            if( i == -1 )
            {
                std::cerr << " errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND" << std::endl;
                errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND;
                return false;
            }
            currententry.setName( atts.value(i).toStdString() );
            parsestate = PROTOCOL_STATE_ENTRY;
            return true;
        }
        return unknowndepth++;
    }
    void caseProtocolStateEntry( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "longname" )
            return caseProtocolStateEntryLongName( atts );
        else if( localName == "description" )
            return caseProtocolStateEntryDescription( atts );
        else if( localName == "classification" )
            return caseProtocolStateEntryClassification( atts );
        else if( localName == "network" )
            return caseProtocolStateEntryNetwork();
        else if( localName == "security" )
            return caseProtocolStateEntrySecurity( atts );
        else if( localName == "pragma" )
            return caseProtocolStateEntryPragma( atts );
        else
            return unknowndepth++;
    }
        void caseProtocolStateEntryLongName(QXmlAttributes const & atts)
        {
            string tmp = "en";
            loadlongname = currententry.longnamelanguage.empty()
            int i = atts.index( protocolnamespace, "lang" );
            if( i != -1 )
                tmp = atts.value(i).toStdString();
            if( loadlongname )
                currententry.longnamelanguage = tmp;
            return parsestate = PROTOCOL_STATE_LONGNAME;
        }
        void caseProtocolStateEntryDescription(QXmlAttributes const & atts);
        {
            string tmp = "en";
            loaddescription = currententry.descriptionlanguage.empty();
            int i = atts.index(protocolnamespace, "lang");
            if( i != -1 )
                tmp = atts.value(i).toStdString();
            if( loaddescription )
                currententry.descriptionlanguage = tmp;
            return parsestate = PROTOCOL_STATE_DESCRIPTION;
        }
        void caseProtocolStateEntryClassification(QXmlAttributes const & atts)
        {
            int i = atts.index(protocolnamespace, "class");
            if ( i != -1 )
                currententry.classification = atts.value(i).toStdString();
            return parsestate = PROTOCOL_STATE_CLASSIFICATION;
        }
        void caseProtocolStateEntryNetwork()
        {
            return parsestate = PROTOCOL_STATE_NETWORK;
        }
        void caseProtocolStateEntrySecurity(QXmlAttributes const & atts)
        {
            int i = atts.index( protocolnamespace, "threat");
            if( i != -1 )
                currententry.threat = getScore( atts.value(i).toStdString() );
            i = atts.index( protocolnamespace, "falsepos");
            if( i != -1 )
                currententry.fasepos = getScore( atts.value(i).toStdString() );
            return parsestate = PROTOCOL_STATE_SECURITY;
        }
        void caseProtocolStateEntryPragma(QXmlAttributes const & atts);
    void caseProtocolStateNetwork();
        void caseProtocolStateNetworkTCP();
        void caseProtocolStateNetworkUDP();
        void caseProtocolStateNetworkICMP();
        void caseProtocolStateNetworkIP();
    void caseProtocolStateTCP();
    void caseProtocolStateUDP();
    void caseProtocolStateICMP();
    void caseProtocolStateIP();
    void caseProtocolStateSrcDest()
        void caseProtocolStateSrcDestPort();
        void caseProtocolStateSrcDestRange();

};


































