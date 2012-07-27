

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

    //I think alot of these could go away with proper use of the passed in variables
    //for startElement and end element and the like
    string protocolnamespace,   //!<
    linesattr,                  //!<
    nameattr,                   //!<
    portnumattr,                //!<
    portstartattr,              //!<
    portendattr,                //!<
    threatattr,                 //!<
    falseposattr,               //!<
    sourceattr,                 //!<
    destattr,                   //!<
    directionattr,              //!<
    valueattr,                  //!<
    codeattr,                   //!<
    classattr,                  //!<
    langattr,                   //!<
    protocolattr;               //!<
    std::vector<string> parseerror;
    std::vector<string> languagelist;
    bool loaddescription;
    bool loadlongname;

    //! States used for Parsing the XML file
    enum ParserState
    {
        PROTOCOL_STATE_OUTSIDE,
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
        protocolnamespace = "";
        linesattr         = "lines";
        nameattr          = "name";
        portnumattr       = "portnum";
        portstartattr     = "start";
        portendattr       = "end";
        threatattr        = "threat";
        falseposattr      = "falsepos";
        sourceattr        = "source";
        destattr          = "dest";
        directionattr     = "direction";
        valueattr         = "value";
        codeattr          = "code";
        classattr         = "class";
        langattr          = "lang";
        protocolattr      = "protocol";

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
bool startElement(QString const & /*namespaceURI*/, )
{
}







};

















