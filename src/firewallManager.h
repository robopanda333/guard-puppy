

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
        PROTOCOL_ERROR_TCP_SRCDEST_UNKNOWN,
        PROTOCOL_ERROR_UDP_SRCDEST_UNKNOWN,
        PROTOCOL_ERROR_ICMP_SRCDEST_UNKNOWN,
        PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND,
        PROTOCOL_ERROR_IP_SRCDEST_UNKNOWN,
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

    //maybe these should be a static member of ProtocolEntry?
    ProtocolEntry::Score getScore( string const & s )
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
    ProtocolEntry::RangeType getRangeType(string const & s)
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
    
    uint8_t getType ( string const & s )
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

//start element Helper case functions
    bool caseProtocolStateOutside( QString const & localName )
    {
        if( localName == "protocoldb" )
            return parsestate = PROTOCOL_STATE_PROTOCOLDB;
        return ++unknowndepth;
    }

    bool caseProtocolStateProtocolDB( QString const & localName, QXmlAttributes const & atts )
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
        return ++unknowndepth;
    }

    bool caseProtocolStateEntry( QString const & localName, QXmlAttributes const & atts )
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
            return ++unknowndepth;
    }

    bool caseProtocolStateEntryLongName( QXmlAttributes const & atts )
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

    bool caseProtocolStateEntryDescription( QXmlAttributes const & atts )
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

    bool caseProtocolStateEntryClassification( QXmlAttributes const & atts )
    {
        int i = atts.index(protocolnamespace, "class");
        if ( i != -1 )
            currententry.classification = atts.value(i).toStdString();
        return parsestate = PROTOCOL_STATE_CLASSIFICATION;
    }

    bool caseProtocolStateEntryNetwork()
    {
        return parsestate = PROTOCOL_STATE_NETWORK;
    }

    bool caseProtocolStateEntrySecurity( QXmlAttributes const & atts )
    {
        int i = atts.index( protocolnamespace, "threat");
        if( i != -1 )
            currententry.threat = getScore( atts.value(i).toStdString() );
        i = atts.index( protocolnamespace, "falsepos");
        if( i != -1 )
            currententry.fasepos = getScore( atts.value(i).toStdString() );
        return parsestate = PROTOCOL_STATE_SECURITY;
    }

    bool caseProtocolStateEntryPragma( QXmlAttributes const & atts )
    {
        int i = atts.index( protocolnamespace, "name" );
        if( i != -1 )
            currententry.pragma[atts.value(i).toStdString()];
        return parsestate = PROTOCOL_STATE_ENTRY_PRAGMA;
    }

    bool caseProtocolStateNetwork( QString const & localName, QXmlAttributes const & atts )
    {
        int i;
        uint8_t type = getType( localName );
        currentnetuse = ProtocolNetUse();   //i don't like this. i think i want to just have "current protocol", or get pdb.last()
                                            //and then add a new netuse to that. and then modify it in place. like
                                            //net * t = pdb.last().addNewNet();
                                            //t->dostuff();
        currentnetuse.setType( type );
        //Handle Protocol Attribute
        if(type == IPPROTO_IP)
        {
            i = atts.index( protocolnamespace, "protocol" );
            if( i== -1)
            {
                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND;
                return false;
            }
            string temp = atts.value(i).toStdString();
            try
            { currentnetuse.setType( boost::lexical_cast<uint8_t>(temp) ); }
            catch( ... )
            {
                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT;//not that it should be.
                return false;//this removes the need to range check.
            }
        }

        //Handle Source Attribute
        bool good = caseProtocolStateNetworkHandleAttribute( atts, type, &currentnetuse, &ProtocolNetUse::setSourceRole, "source" );
        if(!good)
            return false;
        //Handle Dest Attribute
        good = caseProtocolStateNetworkHandleAttribute( atts, type, &currentnetuse, &ProtocolNetUse::setDestRole, "dest" );
        if(!good)
            return false;
        //Handle Direction Attribute
        i = atts.index( protocolnamespace, "direction" );
        if( i != -1 )
            currentnetuse.setBidirectional(true);

        switch(type)
        {
            case IPPROTO_TCP:  parsestate = PROTOCOL_STATE_TCP;  break;
            case IPPROTO_UDP:  parsestate = PROTOCOL_STATE_UDP;  break;
            case IPPROTO_ICMP: parsestate = PROTOCOL_STATE_ICMP; break;
            case IPPROTO_IP:   parsestate = PROTOCOL_STATE_IP;   break;
            default: return false;
        }
        return true;
    }

    bool caseProtocolStateNetworkHandleAttribute( QXmlAttributes const & atts, uint8_t type, ProtocolNetUse * cur, void (ProtocolNetUse::*f)(ProtocolNetUse::Role), string sym)
    {
        int i = atts.index( protocolnamespace, sym.c_str() );
        if( i != -1 )
        {
            string t = atts.value(i).toStdString();
            if( t == "client" )
                cur->*f( ProtocolNetUse::CLIENT );
            else if( t == "server" )
                cur->*f( ProtocolNetUse::SERVER );
            else
            {
                switch(type)
                {
                    case IPPROTO_TCP:  errorstate = PROTOCOL_ERROR_TCP_SRCDEST_UNKNOWN;
                        break;
                    case IPPROTO_UDP:  errorstate = PROTOCOL_ERROR_UDP_SRCDEST_UNKNOWN;
                        break;
                    case IPPROTO_ICMP: errorstate = PROTOCOL_ERROR_ICMP_SRCDEST_UNKNOWN;
                        break;
                    case IPPROTO_IP:   errorstate = PROTOCOL_ERROR_IP_SRCDEST_UNKNOWN;
                        break;
                    default:
                        break;
                }
                return false;
            }
        }
        return true;
    }

    bool caseProtocolStateTCP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "source" )
            return parsestate = PROTOCOL_STATE_TCP_SOURCE;
        if( localName == "dest" )
            return parsestate = PROTOCOL_STATE_TCP_DEST;
        if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            return parsestate = PROTOCOL_STATE_TCP_DESCRIPTION;
        }
        if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            return parsestate = PROTOCOL_STATE_TCP_PRAGMA;
        }
        return ++unknowndepth;
    }

    bool caseProtocolStateUDP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "source" )
            return parsestate = PROTOCOL_STATE_UDP_SOURCE;
        if( localName == "dest" )
            return parsestate = PROTOCOL_STATE_UDP_DEST;
        if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            return parsestate = PROTOCOL_STATE_UDP_DESCRIPTION;
        }
        if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            return parsestate = PROTOCOL_STATE_UDP_PRAGMA;
        }
        return ++unknowndepth;
        
    }

    bool caseProtocolStateICMP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "type" )
        {
            currentnetuse.SourceRangeCode(-1);
                        //we either don't specify the code, or there isn't one associated with the type
            int i = atts.index( protocolnamespace, "value" )
            if( i == -1 )
            {
                errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND;
                return false;
            }
            currentnetuse.SourceRangeType( boost::lexical_cast<uint8_t>( atts.value(i).toStdString() ) );

            i = atts.index( protocolnamespace, "code" );
            if( i != -1 )
                currentnetuse.SourceRangeCode( boost::lexical_cast<uint8_t>( atts.value(i).toStdString() ) );
            return parsestate = PROTOCOL_STATE_ICMP_TYPE;
        }
        if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            return parsestate = PROTOCOL_STATE_UDP_DESCRIPTION;
        }
        if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            return parsestate = PROTOCOL_STATE_UDP_PRAGMA;
        }
        return ++unknowndepth;
    }

    bool caseProtocolStateIP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            return parsestate = PROTOCOL_STATE_UDP_DESCRIPTION;
        }
        if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            return parsestate = PROTOCOL_STATE_UDP_PRAGMA;
        }
        return ++unknowndepth;
    }

    bool caseProtocolStateNetDescriptionLanguage(QXmlAttributes & atts)
    {
        string tmp = "en";
        int i = atts.index( protocolnamespace, "lang" )
        if( i != -1 )
            tmp = atts.value(i).toStdString();
        loaddescription = currentnetuse.descriptionlanguage.empty();
        if( loaddescription == true )
            currentnetuse.descriptionlanguage = tmp;
    }

    bool caseProtocolStateSrcDest( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "port" )
            return caseProtocolStateSrcDestPort(atts);
        if( localName == "range" )
            return caseProtocolStateSrcDestPort(atts);
        return ++unknowndepth;
    }

    /*!
     *  starting to think that the xml parser should have "currentnetusedetail" or some future variant of it,
     *  as well as currentnetuse. this gets rid of my problem where it was only used for parsing but always in memory
     *  because this class only exists durring construction of the firewall manager.
     *  but it still is annoying to me because then i need to have the functionality to modularly build a  detail, whereas right now
     *  i like the idea of no ablility to look at or touch them outside of access member functions of the protocolEntry.
     *  i guess i could have the class friend the xmlparser... :/
     *  it could just be a pointer to the last defined PortRange. that is essentially what it was anyway.
     */

    void caseProtocolStateSrcDestPort( QXmlAttributes const & atts )
    {//the main problem is right here i don't care if it is a src or dst, it is the same either way
    currentnetusedetail = ProtocolNetUseDetail();
        int i = atts.index( protocolnamespace, "portnum" );
        if( i == -1 )
        {
            errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND;
            return false;
        }
        string s = atts.value(i).toStdString();
        ProtocolEntry::RangeType type( s );
        currentnetusedetail.setRangeType(type);
        if(type == ProtocolEntry::RANGE)//the other range types' ports are decided elsewhere
            currentnetusedetail.setPort( boost::lexical_cast<uint16_t>(s) );
        switch(parsestate)
        {//this makes me want to do some verilog like cleverness with the state values.
            case PROTOCOL_STATE_TCP_SOURCE:
                return parsestate = PROTOCOL_STATE_TCP_SOURCE_PORT;
            case PROTOCOL_STATE_UDP_SOURCE:
                return parsestate = PROTOCOL_STATE_UDP_SOURCE_PORT;
            case PROTOCOL_STATE_TCP_DEST:
                return parsestate = PROTOCOL_STATE_TCP_DEST_PORT;
            case PROTOCOL_STATE_UDP_DEST:
                return parsestate = PROTOCOL_STATE_TCP_DEST_PORT;
            default:
                return true;
        }
    }

    void caseProtocolStateSrcDestRange()
    {
    currentnetusedetail = ProtocolNetUseDetail();

        int i = atts.index( protocolnamespace, "start" );
        if( i == -1 )
        {
            errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND;
            return false;
        }
        currentnetusedetail.setStartPort( boost::lexical_cast<uint16_t>( atts.value(i).toStdString() ) );

        i = atts.index( protocolnamespace, "end" );
        if( i == -1 )
        {
            errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND;
            return false;
        }
        currentnetusedetail.setEndPort( boost::lexical_cast<uint16_t>( atts.value(i).toStdString() ) );

        switch(parsestate)
        {
            case PROTOCOL_STATE_TCP_SOURCE:
                return parsestate = PROTOCOL_STATE_TCP_SOURCE_PORTRANGE;
            case PROTOCOL_STATE_UDP_SOURCE:
                return parsestate = PROTOCOL_STATE_UDP_SOURCE_PORTRANGE;
            case PROTOCOL_STATE_TCP_DEST:
                return parsestate = PROTOCOL_STATE_TCP_DEST_PORTRANGE;
            case PROTOCOL_STATE_UDP_DEST:
                return parsestate = PROTOCOL_STATE_TCP_DEST_PORTRANGE;
            default:
                return true;
        }
    }

};


































