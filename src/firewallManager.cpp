


#include <netinet/in.h>
#include <vector>
#include <string>
#include <iostream>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include "firewallManager.h"



#define protocolnamespace ""



///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
//ProtocolXMLParser Class Method Definitions
///////////////////////////////////////////////////////////////////////////////
ProtocolXMLParser::ProtocolXMLParser( std::string const & filename, ProtocolDB _pdb ): pdb(_pdb)
{
    languagelist.push_back( "en" );//we want at least one permited language
    loadDB(filename);
}

bool ProtocolXMLParser::loadDB(std::string const & filename)
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

bool ProtocolXMLParser::startDocument()
{
    parsestate = PROTOCOL_STATE_OUTSIDE;
    errorstate = PROTOCOL_ERROR_NOERROR;
    unknowndepth = 0;
    return true;
}

bool ProtocolXMLParser::startElement(QString const &, QString const & localName, QString const &, QXmlAttributes const & atts )
{
    if(unknowndepth > 0)
        return unknowndepth++;

    switch(parsestate)
    {
        case PROTOCOL_STATE_OUTSIDE:
            return caseProtocolStateOutside(localName);
        case PROTOCOL_STATE_PROTOCOLDB:
            return caseProtocolStateProtocolDB(localName, atts);
        case PROTOCOL_STATE_ENTRY:
            return caseProtocolStateEntry(localName, atts);
        case PROTOCOL_STATE_NETWORK:
            return caseProtocolStateNetwork(localName, atts);
        case PROTOCOL_STATE_TCP:
            return caseProtocolStateTCP(localName, atts);
        case PROTOCOL_STATE_UDP:
            return caseProtocolStateUDP(localName, atts);
        case PROTOCOL_STATE_ICMP:
            return caseProtocolStateICMP(localName, atts);
        case PROTOCOL_STATE_IP:
            return caseProtocolStateIP(localName, atts);
        case PROTOCOL_STATE_TCP_SOURCE: case PROTOCOL_STATE_UDP_SOURCE: case PROTOCOL_STATE_TCP_DEST: case PROTOCOL_STATE_UDP_DEST:
            return caseProtocolStateSrcDest(localName, atts);
        default:
            return unknowndepth++;
    }
}

bool ProtocolXMLParser::endElement(QString const &, QString const &, QString const &)
{
    if(unknowndepth>0)
    {
        unknowndepth--;
        return true;
    }
    switch(parsestate)
    {
        case PROTOCOL_STATE_PROTOCOLDB:
            parsestate = PROTOCOL_STATE_FINISHED;   break;

        case PROTOCOL_STATE_ENTRY:
            //addProtocolEntry( currententry );
            parsestate = PROTOCOL_STATE_PROTOCOLDB; break;

        case PROTOCOL_STATE_LONGNAME: case PROTOCOL_STATE_DESCRIPTION: case PROTOCOL_STATE_SECURITY: case PROTOCOL_STATE_NETWORK: case PROTOCOL_STATE_CLASSIFICATION: case PROTOCOL_STATE_ENTRY_PRAGMA:
            parsestate = PROTOCOL_STATE_ENTRY;      break;

        case PROTOCOL_STATE_TCP: case PROTOCOL_STATE_UDP: case PROTOCOL_STATE_ICMP: case PROTOCOL_STATE_IP:
            //currententry.addNetwork( currentnetuse );
            parsestate = PROTOCOL_STATE_NETWORK;    break;

        case PROTOCOL_STATE_TCP_SOURCE: case PROTOCOL_STATE_TCP_DEST: case PROTOCOL_STATE_TCP_DESCRIPTION: case PROTOCOL_STATE_TCP_PRAGMA:
            parsestate = PROTOCOL_STATE_TCP;        break;

        case PROTOCOL_STATE_UDP_SOURCE: case PROTOCOL_STATE_UDP_DESCRIPTION: case PROTOCOL_STATE_UDP_PRAGMA:
            parsestate = PROTOCOL_STATE_UDP;        break;

        case PROTOCOL_STATE_ICMP_TYPE:
            //currentnetuse.addSource( currentnetusedetail ); //fallthrough intentional
        case PROTOCOL_STATE_ICMP_DESCRIPTION: case PROTOCOL_STATE_ICMP_PRAGMA:
            parsestate = PROTOCOL_STATE_ICMP;       break;

        case PROTOCOL_STATE_IP_DESCRIPTION: case PROTOCOL_STATE_IP_PRAGMA:
            parsestate = PROTOCOL_STATE_IP;         break;

        case PROTOCOL_STATE_TCP_SOURCE_PORT: case PROTOCOL_STATE_TCP_SOURCE_PORTRANGE:
            //currentnetuse.addSource( currentnetusedetail );
            parsestate = PROTOCOL_STATE_TCP_SOURCE; break;

        case PROTOCOL_STATE_TCP_DEST_PORT: case PROTOCOL_STATE_TCP_DEST_PORTRANGE:
            //currentnetuse.addDest( currentnetusedetail );
            parsestate = PROTOCOL_STATE_TCP_DEST;   break;

        case PROTOCOL_STATE_UDP_SOURCE_PORT: case PROTOCOL_STATE_UDP_SOURCE_PORTRANGE:
            //currentnetuse.addSource( currentnetusedetail );
            parsestate = PROTOCOL_STATE_UDP_SOURCE; break;

        case PROTOCOL_STATE_UDP_DEST_PORT: case PROTOCOL_STATE_UDP_DEST_PORTRANGE:
            //currentnetuse.addDest( currentnetusedetail );
            parsestate = PROTOCOL_STATE_UDP_DEST;   break;

        default: return false;
    }
    return true;
}

bool ProtocolXMLParser::characters( QString const & ch )
    {
        if( unknowndepth )
            return true;
        switch( parsestate )
        {
            case PROTOCOL_STATE_LONGNAME:
                if( loadlongname )
                    currententry.setLongName(ch.toStdString());
                return true;
            case PROTOCOL_STATE_DESCRIPTION:
                if( loaddescription )
                    currententry.setDescription(ch.toStdString());
                return true;
            case PROTOCOL_STATE_ENTRY_PRAGMA:
                currententry.pragma[lastPragmaName] = ch.toStdString();
                return true;
            case PROTOCOL_STATE_TCP_DESCRIPTION: case PROTOCOL_STATE_UDP_DESCRIPTION: case PROTOCOL_STATE_ICMP_DESCRIPTION:
                if( loaddescription )
                    currentnetuse.description = ch.toStdString();
                return true;
            case PROTOCOL_STATE_TCP_PRAGMA: case PROTOCOL_STATE_UDP_PRAGMA: case PROTOCOL_STATE_ICMP_PRAGMA:
                currentnetuse.pragma[lastPragmaName]=ch.toStdString();
                return true;
            default:
                return true;
        }
    }

    bool ProtocolXMLParser::caseProtocolStateOutside( QString const & localName )
    {
        if( localName == "protocoldb" )
            return (parsestate = PROTOCOL_STATE_PROTOCOLDB);
        return ++unknowndepth;
    }

    bool ProtocolXMLParser::caseProtocolStateProtocolDB( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "protocol" )
        {
            ProtocolEntry n;
            currententry = n;
            int i = atts.index( protocolnamespace, "name" );
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

    bool ProtocolXMLParser::caseProtocolStateEntry( QString const & localName, QXmlAttributes const & atts )
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

    bool ProtocolXMLParser::caseProtocolStateEntryLongName( QXmlAttributes const & atts )
    {
        std::string tmp = "en";
        loadlongname = currententry.longNameLanguage.empty();
        int i = atts.index( protocolnamespace, "lang" );
        if( i != -1 )
            tmp = atts.value(i).toStdString();
        if( loadlongname )
            currententry.longNameLanguage = tmp;
        parsestate = PROTOCOL_STATE_LONGNAME;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateEntryDescription( QXmlAttributes const & atts )
    {
        std::string tmp = "en";
        loaddescription = currententry.descriptionLanguage.empty();
        int i = atts.index(protocolnamespace, "lang");
        if( i != -1 )
            tmp = atts.value(i).toStdString();
        if( loaddescription )
            currententry.descriptionLanguage = tmp;
        parsestate = PROTOCOL_STATE_DESCRIPTION;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateEntryClassification( QXmlAttributes const & atts )
    {
        int i = atts.index(protocolnamespace, "class");
        if ( i != -1 )
            currententry.classification = atts.value(i).toStdString();
        parsestate = PROTOCOL_STATE_CLASSIFICATION;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateEntryNetwork()
    {
        parsestate = PROTOCOL_STATE_NETWORK;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateEntrySecurity( QXmlAttributes const & atts )
    {
        int i = atts.index( protocolnamespace, "threat");
        if( i != -1 )
            currententry.threat = getScore( atts.value(i).toStdString() );
        i = atts.index( protocolnamespace, "falsepos");
        if( i != -1 )
            currententry.falsepos = getScore( atts.value(i).toStdString() );
        parsestate = PROTOCOL_STATE_SECURITY;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateEntryPragma( QXmlAttributes const & atts )
    {
        int i = atts.index( protocolnamespace, "name" );
        if( i != -1 )
            currententry.pragma[atts.value(i).toStdString()];
        parsestate = PROTOCOL_STATE_ENTRY_PRAGMA;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateNetwork( QString const & localName, QXmlAttributes const & atts )
    {
        int i;
        uint8_t type = getType( localName.toStdString() );
        currentnetuse = ProtocolEntry::ProtocolNet();
                                            //i don't like this. i think i want to just have "current protocol", or get pdb.last()
                                            //and then add a new netuse to that. and then modify it in place. like
                                            //net * t = pdb.last().addNewNet();
                                            //t->dostuff();
        currentnetuse.netType = type;
        //Handle Protocol Attribute
        if(type == IPPROTO_IP)
        {
            i = atts.index( protocolnamespace, "protocol" );
            if( i== -1)
            {
                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND;
                return false;
            }
            std::string temp = atts.value(i).toStdString();
            try
            { currentnetuse.netType =  boost::lexical_cast<uint8_t>(temp); }
            catch( ... )
            {
                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_FOUND;//not that it should be.
                return false;//this removes the need to range check.
            }
        }

        //Handle Source Attribute
        bool good = caseProtocolStateNetworkHandleAttribute( atts, type, &currentnetuse, &ProtocolEntry::ProtocolNet::setSourceRole, "source" );
        if(!good)
            return false;
        //Handle Dest Attribute
        good = caseProtocolStateNetworkHandleAttribute( atts, type, &currentnetuse, &ProtocolEntry::ProtocolNet::setDestRole, "dest" );
        if(!good)
            return false;
        //Handle Direction Attribute
        i = atts.index( protocolnamespace, "direction" );
        if( i != -1 )
            currentnetuse.bidirectional = true;

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

    bool ProtocolXMLParser::caseProtocolStateNetworkHandleAttribute( QXmlAttributes const & atts, uint8_t type, ProtocolEntry::ProtocolNet * cur, void (ProtocolEntry::ProtocolNet::*f)(ProtocolEntry::ProtocolNet::Role), std::string sym)
    {
        int i = atts.index( protocolnamespace, sym.c_str() );
        if( i != -1 )
        {
            std::string t = atts.value(i).toStdString();
            if( t == "client" )
                (cur->*f)( ProtocolEntry::ProtocolNet::CLIENT );//the parens around cur->*f is required?! the hell.
            else if( t == "server" )
                (cur->*f)( ProtocolEntry::ProtocolNet::SERVER );
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

    bool ProtocolXMLParser::caseProtocolStateTCP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "source" )
            parsestate = PROTOCOL_STATE_TCP_SOURCE;
        else if( localName == "dest" )
            parsestate = PROTOCOL_STATE_TCP_DEST;
        else if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            parsestate = PROTOCOL_STATE_TCP_DESCRIPTION;
        }
        else if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            parsestate = PROTOCOL_STATE_TCP_PRAGMA;
        }
        else
            ++unknowndepth;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateUDP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "source" )
            parsestate = PROTOCOL_STATE_UDP_SOURCE;
        else if( localName == "dest" )
            parsestate = PROTOCOL_STATE_UDP_DEST;
        else if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            parsestate = PROTOCOL_STATE_UDP_DESCRIPTION;
        }
        else if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            parsestate = PROTOCOL_STATE_UDP_PRAGMA;
        }
        else
            ++unknowndepth;
        return true;
        
    }

    bool ProtocolXMLParser::caseProtocolStateICMP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "type" )
        {
            currentnetuse.sourceRange.code = -1;
                        //we either don't specify the code, or there isn't one associated with the type
            int i = atts.index( protocolnamespace, "value" );
            if( i == -1 )
            {
                errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND;
                return false;
            }
            currentnetuse.sourceRange.type = boost::lexical_cast<uint8_t>( atts.value(i).toStdString() );

            i = atts.index( protocolnamespace, "code" );
            if( i != -1 )
                currentnetuse.sourceRange.code = boost::lexical_cast<uint8_t>( atts.value(i).toStdString() );
            parsestate = PROTOCOL_STATE_ICMP_TYPE;
        }
        else if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            parsestate = PROTOCOL_STATE_ICMP_DESCRIPTION;
        }
        else if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            parsestate = PROTOCOL_STATE_ICMP_PRAGMA;
        }
        else
            ++unknowndepth;
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateIP( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "description" )
        {
            caseProtocolStateDescriptionLanguage( atts );
            parsestate = PROTOCOL_STATE_IP_DESCRIPTION;
        }
        else if( localName == "pragma" )
        {
            int i = atts.index( protocolnamespace, "name" );
            if( i != -1 )
                currentnetuse.pragma[atts.value(i).toStdString()];
            parsestate = PROTOCOL_STATE_IP_PRAGMA;
        }
        else
            ++unknowndepth;
        return true;
    }

    void ProtocolXMLParser::caseProtocolStateDescriptionLanguage(QXmlAttributes const & atts)
    {
        std::string tmp = "en";
        int i = atts.index( protocolnamespace, "lang" );
        if( i != -1 )
            tmp = atts.value(i).toStdString();
        loaddescription = currentnetuse.descriptionLanguage.empty();
        if( loaddescription == true )
            currentnetuse.descriptionLanguage = tmp;
    }

    bool ProtocolXMLParser::caseProtocolStateSrcDest( QString const & localName, QXmlAttributes const & atts )
    {
        if( localName == "port" )
            return caseProtocolStateSrcDestPort(atts);
        if( localName == "portrange" )
            return caseProtocolStateSrcDestRange(atts);
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

    bool ProtocolXMLParser::caseProtocolStateSrcDestPort( QXmlAttributes const & atts )
    {//the main problem is right here i don't care if it is a src or dst, it is the same either way
    currentnetusedetail = ProtocolEntry::PortRange();
        int i = atts.index( protocolnamespace, "portnum" );
        if( i == -1 )
        {
            errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND;
            return false;
        }
        std::string s = atts.value(i).toStdString();
        ProtocolEntry::RangeType type = getRangeType( s );
        currentnetusedetail.rangeType = type;
        if(type == ProtocolEntry::RANGE)//the other range types' ports are decided elsewhere
            currentnetusedetail.start = currentnetusedetail.end =  boost::lexical_cast<uint16_t>(s);
        parsestate = (ParserState)(parsestate|2);
        return true;
    }

    bool ProtocolXMLParser::caseProtocolStateSrcDestRange( QXmlAttributes const & atts )
    {
     currentnetusedetail = ProtocolEntry::PortRange();

        int i = atts.index( protocolnamespace, "start" );
        if( i == -1 )
        {
            errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND;
            return false;
        }
        currentnetusedetail.start = boost::lexical_cast<uint16_t>( atts.value(i).toStdString() );

        i = atts.index( protocolnamespace, "end" );
        if( i == -1 )
        {
            errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND;
            return false;
        }
        currentnetusedetail.end = boost::lexical_cast<uint16_t>( atts.value(i).toStdString() );
        parsestate = (ParserState)(parsestate|4);
        return true;
    }

