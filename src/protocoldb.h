/***************************************************************************
  protocoldb.h
  -------------------
begin                : Thu Nov 23 09:00:22 CET 2000
copyright            : (C) 2000-2001 by Simon Edwards
email                : simon@simonzone.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
#pragma once

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

#include <boost/spirit/home/phoenix/core.hpp>
#include <boost/spirit/home/phoenix/operator.hpp>
#include <boost/spirit/home/phoenix/bind.hpp>


#include <QXmlDefaultHandler>

/*

   Here we go. A ProtocolDB object holds the whole protocol database. There
   is usually only one instance of this. The ProtocolDB object holds a list of
   ProtocolEntry objects. Each ProtocolEntry holds the info about one particualar
   network protocol. In turn a ProtocolEntry object holds a list of
   ProtocolNetUse objects. ProtocolNetUse objects hold information about one way
   that the protocol uses the network. By this I mean something like a TCP
   connection etc. For example. Looking at the diagram below which shows
   troublesome normal FTP, we see that FTP uses two connections. One from the
   Client to the Server to control the session, and one back from the server to
   the client to transmit files.

    __________   Control      ___________
   /          \  ----TCP---> /           \
  | FTP Client |            |  FTP Server |
   \__________/  <----TCP--- \___________/
   Data

   Each of these connections is represented in the database by a ProtocolNetUse
   object describing what kind of IP protocol is used (TCP, UDP etc), which
   party initiates the connection to who, and also what source/dest ports are
   used etc.

   The whole idea of the Protocol Database is to capture the info in diagrams
   like the one above, instead of only just recording port numbers without any
   info about how a protocol actually uses them.

 */

    /*!
    **  \struct Contains the dynamic port range
    */
/*
 *  seems like there should only ever be one of these, and it should always exist inside
 *  the firewall, not anywhere else. Each protocol decides for itself to be Dynamic, but
 *  the firewall should get to say what that means.
 */
struct PortRangeInfo
{
    uint dynamicStart;
    uint dynamicEnd;

    /*!
    **  \brief creates a dynamic port range with decent defaults
    */
    PortRangeInfo(uint s = 1024, uint e = 65535 )
        : dynamicStart( s ), dynamicEnd( e )
    {
    }
};

    /*!
    **  \brief All the kinds of port ranges there are
    */
enum RangeType
{
    PORTRANGE_RANGE=0,
    PORTRANGE_ANY,
    PORTRANGE_PRIVILEGED,
    PORTRANGE_NONPRIVILEGED,
    PORTRANGE_DYNAMIC
};


    /*!
    **  \brief the kinds of entities we support.
    */
enum NetworkEntity
{
    ENTITY_SERVER,
    ENTITY_CLIENT
};

enum Score
{
    SCORE_UNKNOWN=0,
    SCORE_LOW,
    SCORE_MEDIUM,
    SCORE_HIGH
};

//Holds a single port range
class ProtocolNetUseDetail
{
    RangeType rangetype;
    union
    {
        uint start; // tcmp, udp
        uint type;  // icmp
    };
    union
    {
        uint end;   // tcp, udp
        int code;   // icmp
    };
public:

    ProtocolNetUseDetail( RangeType const & _rangetype=PORTRANGE_RANGE, uint _start=0, uint _end=0)
     : rangetype( _rangetype ), start( _start ), end( _end )
    {
    }

    std::string getRangeString() const
    {
        std::stringstream result;
        if (start == end)
            result << start;
        else
            result << start << ":" << end;
        return result.str();
    }

    ~ProtocolNetUseDetail()
    {
    }

    bool inRange( uint port ) const
    {
        return port >= start && port <= end;
    }

    void setRangeType( RangeType const & r ) { rangetype = r; }
    RangeType const & getRangeType() const { return rangetype; }

    void setStartPort(uint p)
    {
        start = p;
        if(start > end)
            end = p;
    }
    void setEndPort(uint p)
    {
        end = p;
        if ( start > end)
            start = p;
    }
    uint getStart(PortRangeInfo const * ri = 0 ) const
    {
        switch(rangetype)
        {
            case PORTRANGE_RANGE:            return start;
            case PORTRANGE_ANY:              return 0;
            case PORTRANGE_PRIVILEGED:       return 0;
            case PORTRANGE_NONPRIVILEGED:    return 1024;
            case PORTRANGE_DYNAMIC: default: return ri==0 ? 1024 : ri->dynamicStart;
        }
    }
    uint getEnd(PortRangeInfo const * ri = 0 ) const
    {
        switch(rangetype)
        {
            case PORTRANGE_RANGE:            return end;
            case PORTRANGE_ANY:              return 65535;
            case PORTRANGE_PRIVILEGED:       return 1023;
            case PORTRANGE_NONPRIVILEGED:    return 65535;
            case PORTRANGE_DYNAMIC: default: return ri==0 ? 65535 : ri->dynamicEnd;
        }
    }

    void setCode( int c ) { code = c; }
    void setType( uint c ) { type = c; }
    int getCode() const { return code; }
    uint getType() const { return type; }

    void print() const
    {
        fprintf(stderr,"[ Start: %u End: %u ]",
                start,end);
    }
};

class ProtocolNetUse
{
public:
    std::string   descriptionlanguage;
    std::string   description;
    uchar         type;    // IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP
    bool          bidirectional;    // For UDP.

    NetworkEntity source;
    NetworkEntity dest;

    ProtocolNetUseDetail sourcedetail;
    ProtocolNetUseDetail destdetail;

    std::map< std::string, std::string > pragma;
    std::string lastPragmaName;

    ProtocolNetUse(uchar t = IPPROTO_TCP, bool bi = true, NetworkEntity sr = ENTITY_CLIENT, NetworkEntity des = ENTITY_SERVER)
    : sourcedetail(PORTRANGE_ANY), destdetail(PORTRANGE_ANY)
    {
        type = t;
        source = sr;
        dest = des;
        bidirectional = bi;
    }

    ~ProtocolNetUse()
    { }

    void addPragmaValue( std::string const & value )
    {
        std::cout << "Pragma " << lastPragmaName << " = " << value << std::endl;
        pragma[ lastPragmaName ] = value;
    }


    void  setType( uchar t ) { type = t; }
    uchar getType() const { return type; }   // IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP
    //the next 2 functions are really poorly named.
    void  setSource( NetworkEntity s ) { source = s; }
    void  setDest( NetworkEntity d ) { dest = d; }
    ProtocolNetUseDetail const &  getSource() const { return sourcedetail; }
    ProtocolNetUseDetail &  getSource() { return sourcedetail; }
    ProtocolNetUseDetail const &  getDest() const { return destdetail; }
    ProtocolNetUseDetail &  getDest() { return destdetail; }
    void  setBidirectional( bool b ) { bidirectional = b; }
    bool isBidirectional() const { return (type==IPPROTO_TCP) || bidirectional; }

    void addSource( ProtocolNetUseDetail const & source )
    {
        sourcedetail = source;
    }
    void addDest( ProtocolNetUseDetail const & dest )
    {
        destdetail = dest;
    }



    void print() const
    {

        fprintf(stderr,"[Description: %s ",(const char *)description.c_str());
        switch(type)
        {
            case IPPROTO_TCP:
                fprintf(stderr," Type: tcp ");
                break;

            case IPPROTO_UDP:
                fprintf(stderr," Type: udp ");
                break;

            case IPPROTO_ICMP:
                fprintf(stderr," Type: icmp ");
                break;

            default:
                fprintf(stderr," Type: %d ",(int)type);
                break;
        }
        fprintf(stderr," Source: ");
        sourcedetail.print();
        fprintf(stderr," Dest: ");
        destdetail.print();
        fprintf(stderr,"]");
    }
    bool sourcePortEquals(uint port) const
    {
        return sourcedetail.inRange( port );
    }
    bool destPortEquals(uint port) const
    {
        return destdetail.inRange( port );
    }
    bool icmpTypeCodeEquals(uint type, int code) const
    {
        if ( type==sourcedetail.getType() )
        {
            if (sourcedetail.getCode()==-1)
                return true;
            else
                if(sourcedetail.getCode()==code)
                    return true;
        }
        return false;
    }
};

class ProtocolEntry
{
    Score threat;
    Score falsepos;

    std::string name;
    std::string classification;
    std::string longname;
    std::string description;
    std::string longnamelanguage;
    std::string descriptionlanguage;

//i don't really know what these are about
    std::string lastPragmaName;
    std::map< std::string, std::string > pragma;
public:
    friend class ProtocolDB;

    std::vector< ProtocolNetUse > networkuse;

    void addPragmaValue( std::string const & value )
    {
        std::cout << "Pragma " << lastPragmaName << " = " << value << std::endl;
        pragma[ lastPragmaName ] = value;
    }

    void addNetwork( ProtocolNetUse const & net )
    {
        networkuse.push_back( net );
    }
    void deleteNetwork( uint n )
    {
        networkuse.erase(networkuse.begin()+n);
    }

    ProtocolEntry( std::string const & _name = "" )
     : name( _name )
    {
        threat         = SCORE_UNKNOWN;
        falsepos       = SCORE_UNKNOWN;
        classification = "Unknown";
    }

    ~ProtocolEntry()
    {

    }

    void print() const
    {

        fprintf(stderr,"[ Name: %s Longname: %s Threat: ",name.c_str(),longname.c_str());
        switch(threat)
        {
            case SCORE_LOW:
                fprintf(stderr,"low");
                break;
            case SCORE_MEDIUM:
                fprintf(stderr,"medium");
                break;
            case SCORE_HIGH:
                fprintf(stderr,"high");
                break;
            default:
                fprintf(stderr,"unknown");
                break;
        }
        fprintf(stderr," Classification: ");

        if(classification != "")
            std::cerr << classification;

        BOOST_FOREACH( ProtocolNetUse const & x, networkuse )
        {
            x.print();
        }
        fprintf(stderr,"]");
    }

    std::string getName() const           { return name; }
    std::string getLongname() const       { return longname; }
    void setName( std::string const & n ) { name = n; longname = n; }
    std::string getDescription() const    { return description; }

    std::string getClassification() const { return classification; }
    void setClassification(std::string s) { classification = s; }

    std::vector<uchar> getTypes() const
    {
        std::vector<uchar> temp;
        BOOST_FOREACH( ProtocolNetUse const & nu, networkuse)
            temp.push_back( nu.getType() );
        return temp;
    }
    void setType(uchar t, int j)
    {
        networkuse[j].setType(t);
    }

    std::vector<std::string> getRangeStrings() const
    {
        std::vector<std::string> temp;
        BOOST_FOREACH( ProtocolNetUse const & nu, networkuse)
            temp.push_back( nu.getDest().getRangeString() );
        return temp;
    }

    std::vector<uint> getStartPorts() const
    {
        std::vector<uint> temp;
        BOOST_FOREACH( ProtocolNetUse const & nu, networkuse)
            temp.push_back( nu.getDest().getStart() );
        return temp;
    }
    void setStartPort(uint i, int j)
    {
        networkuse[j].getDest().setStartPort(i);
    }

    std::vector<uint> getEndPorts() const
    {
        std::vector<uint> temp;
        BOOST_FOREACH( ProtocolNetUse const & nu, networkuse)
            temp.push_back( nu.getDest().getEnd() );
        return temp;
    }
    void setEndPort(uint i, int j)
    {
        networkuse[j].getDest().setEndPort(i);
    }

    std::vector<bool> getBidirectionals() const
    {
        std::vector<bool> temp;
        BOOST_FOREACH( ProtocolNetUse const & nu, networkuse)
            temp.push_back( nu.isBidirectional() );
        return temp;
    }
    void setBidirectional(bool on, int j)
    {
        networkuse[j].setBidirectional( on );
    }

};

class ProtocolDB : public QXmlDefaultHandler
{
    std::vector< ProtocolEntry > protocolDataBase;

//i really hate these...
    ProtocolNetUse currentnetuse;
    ProtocolNetUseDetail currentnetusedetail;
//TODO replace all instances of currententry with protocolDataBase[protocolDataBase.size()]
//                              currentnetuse with protocolDataBase[protocolDataBase.size()].getNetuse()[netusesize]
//                              and similar for currentnetusedetail

    int unknowndepth;   // This is so that we can skip unknown tags.
    std::string protocolnamespace, linesattr,  nameattr,     portnumattr, portstartattr,
                portendattr,       threatattr, falseposattr, sourceattr,  destattr,
                directionattr,     valueattr,  codeattr,     classattr,   langattr,
                protocolattr;

    std::vector< std::string > parseerror;
    std::vector<std::string> languagelist;
    bool loaddescription;
    bool loadlongname;


    // Go state machine go! XML parser states.
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
    };
    ParserState parsestate;

    // XML parser error codes.
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
    };
    ErrorState errorstate;
public:
    ProtocolDB( std::string const & filename )
     :  protocolnamespace(""),  linesattr("lines"), nameattr("name"),           portnumattr("portnum"),
        portstartattr("start"), portendattr("end"), threatattr("threat"),       falseposattr("falsepos"),
        sourceattr("source"),   destattr("dest"),   directionattr("direction"), valueattr("value"),
        codeattr("code"),       classattr("class"), langattr("lang"),           protocolattr("protocol")
    {
        std::vector< std::string > languages;
        languages.push_back( "english" );
        loadDB( filename, languages );
    }

    ProtocolDB()
    {
    }

    bool loadDB(const std::string &filename, std::vector< std::string > const & languages)
    {
        bool rc;
        parsestate = PROTOCOL_STATE_OUTSIDE;
        errorstate = PROTOCOL_ERROR_NOERROR;
        unknowndepth = 0;

        // Copy the list of permitted languages one by one. Convert things
        // like 'en_GB' to just 'en'.
        BOOST_FOREACH( std::string const & l, languages )
            languagelist.push_back( l.substr(0,2) );

        /*!
        **  \todo Need to eliminate the dependence on QFile
        **       for the XML parsing.
        */
        QFile xmlfile( filename.c_str() );
        if(!xmlfile.open(QIODevice::ReadOnly))
        {
            errorstate = PROTOCOL_ERROR_OPEN_ERROR;
            std::cout << "unable to open: " << filename << std::endl;
            return false;
        }
        QXmlInputSource source(&xmlfile);
        QXmlSimpleReader reader;
        reader.setContentHandler(this);
        reader.setErrorHandler(this);
        parseerror.clear(); //.truncate(0);
        std::cout << "Parsing...";
        if ( reader.parse(source))
        {
            std::cout << "success" << std::endl;
            rc = true;
        }
        else
        {
            std::cout << "failed" << std::endl;
            std::cout << errorString().toStdString() << std::endl;
            rc = false;
        }

        xmlfile.close();
        return rc;
    }
    bool startElement(const QString &/*namespaceURI*/, QString const & localName, const QString &/*qName*/, const QXmlAttributes &atts)
    {
        int i;
        std::string protocolname;
        std::string tmp;
        bool ok;
        int x;

        if(unknowndepth==0)
        {
            switch(parsestate)
            {
                case PROTOCOL_STATE_OUTSIDE:
                    if(localName=="protocoldb")
                    {
                        parsestate = PROTOCOL_STATE_PROTOCOLDB;
//                        i = atts.index(protocolnamespace.c_str(),linesattr.c_str());
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_PROTOCOLDB:
                    if ( localName == "protocol" )
                    {
                        // Fetch the name attribute.
                        i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                        if(i==-1)
                        {
                            std::cerr << "  errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND" << std::endl;
                            errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND;
                            return false;
                        }
                        addProtocolEntry( ProtocolEntry(atts.value(i).toStdString()) );
                        parsestate = PROTOCOL_STATE_ENTRY;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_ENTRY:
                    if(localName=="longname")
                    {
                        loadlongname = false;
                        i = atts.index(protocolnamespace.c_str(),langattr.c_str());
                        if(i!=-1)
                            tmp = atts.value(i).toStdString();
                        else
                            tmp = "en";
                        if( protocolDataBase.back().longnamelanguage.empty())
                        {
                            loadlongname = true;
                            protocolDataBase.back().longnamelanguage = tmp;
                        }

                        parsestate = PROTOCOL_STATE_LONGNAME;
                        return true;
                    }
                    if(localName=="description")
                    {
                        loaddescription = false;
                        i = atts.index(protocolnamespace.c_str(),langattr.c_str());
                        if(i!=-1)
                            tmp = atts.value(i).toStdString();
                        else
                            tmp = "en";

                        if(protocolDataBase.back().descriptionlanguage.empty())
                        {
                            loaddescription = true;
                            protocolDataBase.back().descriptionlanguage = tmp;
                        }
                        parsestate = PROTOCOL_STATE_DESCRIPTION;
                        return true;
                    }
                    if ( localName=="classification" )
                    {
                        i = atts.index(protocolnamespace.c_str(),classattr.c_str());
                        if ( i != -1 )
                        {
                            tmp = atts.value(i).toStdString();
                            protocolDataBase.back().classification = tmp;
                        }
                        parsestate = PROTOCOL_STATE_CLASSIFICATION;
                        return true;
                    }
                    if(localName=="network")
                    {
                        parsestate = PROTOCOL_STATE_NETWORK;
                        return true;
                    }
                    if(localName=="security")
                    {
                        // Grab the threat info
                        i = atts.index(protocolnamespace.c_str(),threatattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="unknown")
                                protocolDataBase.back().threat = SCORE_UNKNOWN;
                            else if(tmp=="low")
                                protocolDataBase.back().threat = SCORE_LOW;
                            else if(tmp=="medium")
                                protocolDataBase.back().threat = SCORE_MEDIUM;
                            else if(tmp=="high")
                                protocolDataBase.back().threat = SCORE_HIGH;
                            else
                            {
                                errorstate = PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN;
                                return false;
                            }
                        }

                        // Grab the falsepos info
                        i = atts.index(protocolnamespace.c_str(),falseposattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="unknown")
                                protocolDataBase.back().falsepos = SCORE_UNKNOWN;
                            else if(tmp=="low")
                                protocolDataBase.back().falsepos = SCORE_LOW;
                            else if(tmp=="medium")
                                protocolDataBase.back().falsepos = SCORE_MEDIUM;
                            else if(tmp=="high")
                                protocolDataBase.back().falsepos = SCORE_HIGH;
                            else
                            {
                                errorstate = PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN;
                                return false;
                            }
                        }
                        parsestate = PROTOCOL_STATE_SECURITY;
                        return true;
                    }

                    if(localName=="pragma")
                    {
                        // Grab the pragma name
                        i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            protocolDataBase.back().lastPragmaName = tmp;
                            protocolDataBase.back().pragma[tmp] = "";
                        }
                        parsestate = PROTOCOL_STATE_ENTRY_PRAGMA;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_NETWORK:
                    if(localName=="tcp")
                    {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( IPPROTO_TCP );
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setSource( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setSource( ENTITY_SERVER );
                            else
                            {
                                std::cerr << "   errorstate = PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN " << std::endl;
                                errorstate = PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN;
                                return false;
                            }
                        }
                        // Handle Dest attribute
                        i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setDest( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setDest( ENTITY_SERVER );
                            else
                            {
                                std::cerr << "   errorstate = PROTOCOL_ERROR_TCP_DEST_UNKNOWN " << std::endl;
                                errorstate = PROTOCOL_ERROR_TCP_DEST_UNKNOWN;
                                return false;
                            }
                        }
                        parsestate = PROTOCOL_STATE_TCP;
                        return true;
                    }
                    if(localName=="udp")
                    {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( IPPROTO_UDP );
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setSource( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setSource( ENTITY_SERVER );
                            else
                            {
                                std::cerr << "   errorstate = PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN" << std::endl;
                                errorstate = PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN;
                                return false;
                            }
                        }
                        // Handle Dest attribute
                        i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setDest( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setDest( ENTITY_SERVER );
                            else
                            {
                                std::cerr << "   errorstate = PROTOCOL_ERROR_UDP_DEST_UNKNOWN" << std::endl;
                                errorstate = PROTOCOL_ERROR_UDP_DEST_UNKNOWN;
                                return false;
                            }
                        }

                        // Check for direction attribute
                        i = atts.index(protocolnamespace.c_str(),directionattr.c_str());
                        if(i!=-1)
                            currentnetuse.setBidirectional( true );
                        parsestate = PROTOCOL_STATE_UDP;
                        return true;
                    }
                    if(localName=="icmp")
                    {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( IPPROTO_ICMP );
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setSource( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setSource( ENTITY_SERVER );
                            else
                            {
                                std::cerr<<"   errorstate = PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN"<<std::endl;
                                errorstate = PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN;
                                return false;
                            }
                        }
                        // Handle Dest attribute
                        i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setDest( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setDest( ENTITY_SERVER );
                            else
                            {
                                std::cerr << "   errorstate = PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN" << std::endl;
                                errorstate = PROTOCOL_ERROR_ICMP_DEST_UNKNOWN;
                                return false;
                            }
                        }
                        parsestate = PROTOCOL_STATE_ICMP;
                        return true;
                    }
                    if(localName=="ip")
                    {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( 0 );    // Dummy.

                        // Handle the Protocol attribute.
                        i = atts.index(protocolnamespace.c_str(),protocolattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            try
                            {
                                ok = true;
                                x = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                            }
                            catch ( ... )
                            {
                                ok = false;
                                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT;
                                return false;
                            }
                            if(x<0 || x>255)
                            {
                                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE;
                                return false;
                            }
                            currentnetuse.setType( x );
                        }
                        else
                        {
                            errorstate = PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND;
                            return false;
                        }
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setSource( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setSource( ENTITY_SERVER );
                            else
                            {
                                errorstate = PROTOCOL_ERROR_IP_SOURCE_UNKNOWN;
                                return false;
                            }
                        }
                        // Handle Dest attribute
                        i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                                currentnetuse.setDest( ENTITY_CLIENT );
                            else if(tmp=="server")
                                currentnetuse.setDest( ENTITY_SERVER );
                            else
                            {
                                errorstate = PROTOCOL_ERROR_IP_DEST_UNKNOWN;
                                return false;
                            }
                        }

                        // Check for direction attribute
                        i = atts.index(protocolnamespace.c_str(),directionattr.c_str());
                        if(i!=-1)
                            currentnetuse.setBidirectional( true );

                        parsestate = PROTOCOL_STATE_IP;
                        return true;
                    }

                    break;

                case PROTOCOL_STATE_TCP:
                    if(localName=="source")
                    {
                        parsestate = PROTOCOL_STATE_TCP_SOURCE;
                        return true;
                    }
                    if(localName=="dest")
                    {
                        parsestate = PROTOCOL_STATE_TCP_DEST;
                        return true;
                    }
                    if(localName=="description")
                    {
                        doNetuseLanguage(atts);
                        parsestate = PROTOCOL_STATE_TCP_DESCRIPTION;
                        return true;
                    }
                    if(localName=="pragma")
                    {
                        // Grab the pragma name
                        i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
                        parsestate = PROTOCOL_STATE_TCP_PRAGMA;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_UDP:
                    if(localName=="source")
                    {
                        parsestate = PROTOCOL_STATE_UDP_SOURCE;
                        return true;
                    }
                    if(localName=="dest")
                    {
                        parsestate = PROTOCOL_STATE_UDP_DEST;
                        return true;
                    }
                    if(localName=="description")
                    {
                        doNetuseLanguage(atts);
                        parsestate = PROTOCOL_STATE_UDP_DESCRIPTION;
                        return true;
                    }
                    if(localName=="pragma")
                    {
                        // Grab the pragma name
                        i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
                        parsestate = PROTOCOL_STATE_UDP_PRAGMA;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_ICMP:
                    if(localName=="type")
                    {
                        currentnetusedetail = ProtocolNetUseDetail();
                        currentnetusedetail.setCode( -1 );
                        // Grab the type number
                        i = atts.index(protocolnamespace.c_str(),valueattr.c_str());
                        if(i==-1)
                        {
                            errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();
                        currentnetusedetail.setType( boost::lexical_cast<uint>(tmp) ); //tmp.toUInt(&ok);

                        // Grab the ICMP code.
                        i = atts.index(protocolnamespace.c_str(),codeattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            currentnetusedetail.setCode( boost::lexical_cast<uint>(tmp)); //tmp.toUInt(&ok);
                        }

                        parsestate = PROTOCOL_STATE_ICMP_TYPE;
                        return true;
                    }
                    if(localName=="description")
                    {
                        doNetuseLanguage(atts);
                        parsestate = PROTOCOL_STATE_ICMP_DESCRIPTION;
                        return true;
                    }
                    if(localName=="pragma")
                    {
                        // Grab the pragma name
                        i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
                        parsestate = PROTOCOL_STATE_ICMP_PRAGMA;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_IP:
                    if(localName=="description")
                    {
                        doNetuseLanguage(atts);
                        parsestate = PROTOCOL_STATE_IP_DESCRIPTION;
                        return true;
                    }
                    if(localName=="pragma")
                    {
                        // Grab the pragma name
                        i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
                        parsestate = PROTOCOL_STATE_IP_PRAGMA;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_TCP_SOURCE:
                case PROTOCOL_STATE_UDP_SOURCE:
                case PROTOCOL_STATE_TCP_DEST:
                case PROTOCOL_STATE_UDP_DEST:
                    if(localName=="port")
                    {
                        currentnetusedetail = ProtocolNetUseDetail();

                        // Grab the port number
                        i = atts.index(protocolnamespace.c_str(),portnumattr.c_str());
                        if(i==-1)
                        {
                            errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();

                        if(tmp=="any")
                        {
                            currentnetusedetail.setRangeType( PORTRANGE_ANY );
                            currentnetusedetail.setEndPort( 65535 );
                        }
                        else if(tmp=="privileged")
                        {
                            currentnetusedetail.setRangeType( PORTRANGE_PRIVILEGED );
                            currentnetusedetail.setEndPort( 1023 );
                        }
                        else if(tmp=="nonprivileged")
                        {
                            currentnetusedetail.setRangeType( PORTRANGE_NONPRIVILEGED );
                            currentnetusedetail.setStartPort( 1024 );
                            currentnetusedetail.setEndPort( 65535 );
                        }
                        else if(tmp=="dynamic")
                        {
                            currentnetusedetail.setRangeType( PORTRANGE_DYNAMIC );
                            currentnetusedetail.setStartPort( 1024 );
                            currentnetusedetail.setEndPort( 65535 );
                        }
                        else
                            currentnetusedetail.setStartPort( boost::lexical_cast<uint>(tmp) ); //tmp.toUInt(&ok);

                        switch(parsestate)
                        {
                            case PROTOCOL_STATE_TCP_SOURCE:
                                parsestate = PROTOCOL_STATE_TCP_SOURCE_PORT;
                                break;
                            case PROTOCOL_STATE_UDP_SOURCE:
                                parsestate = PROTOCOL_STATE_UDP_SOURCE_PORT;
                                break;
                            case PROTOCOL_STATE_TCP_DEST:
                                parsestate = PROTOCOL_STATE_TCP_DEST_PORT;
                                break;
                            case PROTOCOL_STATE_UDP_DEST:
                                parsestate = PROTOCOL_STATE_UDP_DEST_PORT;
                                break;
                            default:
                                break;
                        }
                        return true;
                    }
                    if(localName=="portrange")
                    {
                        currentnetusedetail = ProtocolNetUseDetail();
                        // Grab the start port number
                        i = atts.index(protocolnamespace.c_str(),portstartattr.c_str());
                        if(i==-1)
                        {
                            errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();
                        currentnetusedetail.setStartPort( boost::lexical_cast<uint>(tmp) );

                        // Grab the end port number
                        i = atts.index(protocolnamespace.c_str(),portendattr.c_str());
                        if(i==-1)
                        {
                            errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();
                        currentnetusedetail.setEndPort( boost::lexical_cast<uint>(tmp) );

                        switch(parsestate)
                        {
                            case PROTOCOL_STATE_TCP_SOURCE:
                                parsestate = PROTOCOL_STATE_TCP_SOURCE_PORTRANGE;
                                break;
                            case PROTOCOL_STATE_UDP_SOURCE:
                                parsestate = PROTOCOL_STATE_UDP_SOURCE_PORTRANGE;
                                break;
                            case PROTOCOL_STATE_TCP_DEST:
                                parsestate = PROTOCOL_STATE_TCP_DEST_PORTRANGE;
                                break;
                            case PROTOCOL_STATE_UDP_DEST:
                                parsestate = PROTOCOL_STATE_UDP_DEST_PORTRANGE;
                                break;
                            default:
                                break;
                        }
                        return true;
                    }
                    break;

                default:
                    break;
            }
        }
        unknowndepth++;
        return true;
    }
    bool endElement(const QString &/*namespaceURI*/, const QString &/*localName*/, const QString &/*qName*/)
    {
        if(unknowndepth==0)
        {
            switch(parsestate)
            {
                case PROTOCOL_STATE_PROTOCOLDB:
                    parsestate = PROTOCOL_STATE_FINISHED;
                    return true;

                case PROTOCOL_STATE_ENTRY:
                    // We are just exiting an entry.
                    parsestate = PROTOCOL_STATE_PROTOCOLDB;
                    return true;

                case PROTOCOL_STATE_LONGNAME:
                case PROTOCOL_STATE_DESCRIPTION:
                case PROTOCOL_STATE_SECURITY:
                case PROTOCOL_STATE_NETWORK:
                case PROTOCOL_STATE_CLASSIFICATION:
                case PROTOCOL_STATE_ENTRY_PRAGMA:
                    parsestate = PROTOCOL_STATE_ENTRY;
                    return true;

                case PROTOCOL_STATE_TCP:
                case PROTOCOL_STATE_UDP:
                case PROTOCOL_STATE_ICMP:
                case PROTOCOL_STATE_IP:
                    protocolDataBase.back().addNetwork( currentnetuse ); //networkuse.push_back(currentnetuse);
                    parsestate = PROTOCOL_STATE_NETWORK;
                    return true;

                case PROTOCOL_STATE_TCP_SOURCE:
                case PROTOCOL_STATE_TCP_DEST:
                case PROTOCOL_STATE_TCP_DESCRIPTION:
                case PROTOCOL_STATE_TCP_PRAGMA:
                    parsestate = PROTOCOL_STATE_TCP;
                    return true;

                case PROTOCOL_STATE_UDP_SOURCE:
                case PROTOCOL_STATE_UDP_DEST:
                case PROTOCOL_STATE_UDP_DESCRIPTION:
                case PROTOCOL_STATE_UDP_PRAGMA:
                    parsestate = PROTOCOL_STATE_UDP;
                    return true;

                case PROTOCOL_STATE_ICMP_TYPE:
                    currentnetuse.addSource(currentnetusedetail);
                    parsestate = PROTOCOL_STATE_ICMP;
                    return true;

                case PROTOCOL_STATE_ICMP_DESCRIPTION:
                case PROTOCOL_STATE_ICMP_PRAGMA:
                    parsestate = PROTOCOL_STATE_ICMP;
                    return true;

                case PROTOCOL_STATE_IP_DESCRIPTION:
                case PROTOCOL_STATE_IP_PRAGMA:
                    parsestate = PROTOCOL_STATE_IP;
                    return true;

                case PROTOCOL_STATE_TCP_SOURCE_PORT:
                case PROTOCOL_STATE_TCP_SOURCE_PORTRANGE:
                    currentnetuse.addSource(currentnetusedetail);
                    parsestate = PROTOCOL_STATE_TCP_SOURCE;
                    return true;

                case PROTOCOL_STATE_TCP_DEST_PORT:
                case PROTOCOL_STATE_TCP_DEST_PORTRANGE:
                    currentnetuse.addDest(currentnetusedetail);
                    parsestate = PROTOCOL_STATE_TCP_DEST;
                    return true;

                case PROTOCOL_STATE_UDP_SOURCE_PORT:
                case PROTOCOL_STATE_UDP_SOURCE_PORTRANGE:
                    currentnetuse.addSource(currentnetusedetail);
                    parsestate = PROTOCOL_STATE_UDP_SOURCE;
                    return true;

                case PROTOCOL_STATE_UDP_DEST_PORT:
                case PROTOCOL_STATE_UDP_DEST_PORTRANGE:
                    currentnetuse.addDest(currentnetusedetail);
                    parsestate = PROTOCOL_STATE_UDP_DEST;
                    return true;

                default:
                    return false;
            }
        }
        unknowndepth--;
        return true;
    }
    bool characters(const QString &ch)
    {
        if ( unknowndepth )
            return true;

        switch ( parsestate )
        {
            case PROTOCOL_STATE_LONGNAME:
                if(loadlongname)
                    protocolDataBase.back().longname = ch.toStdString();
                return true;

            case PROTOCOL_STATE_DESCRIPTION:
                if ( loaddescription )
                    protocolDataBase.back().description = ch.toStdString();
                return true;

            case PROTOCOL_STATE_ENTRY_PRAGMA:
                protocolDataBase.back().addPragmaValue(ch.toStdString());
                return true;

            case PROTOCOL_STATE_TCP_DESCRIPTION:
            case PROTOCOL_STATE_UDP_DESCRIPTION:
            case PROTOCOL_STATE_ICMP_DESCRIPTION:
                if ( loaddescription )
                    currentnetuse.description = ch.toStdString();
                return true;

            case PROTOCOL_STATE_TCP_PRAGMA:
            case PROTOCOL_STATE_UDP_PRAGMA:
            case PROTOCOL_STATE_ICMP_PRAGMA:
                currentnetuse.addPragmaValue(ch.toStdString());
                return true;

            default:
                break;
        }
        return true;
    }
    bool error(const QXmlParseException &exception)
    {
        printParseException(exception);
        errorstate = PROTOCOL_ERROR_PARSE_ERROR;
        return false;
    }
    bool fatalError(const QXmlParseException &exception)
    {
        printParseException(exception);
        errorstate = PROTOCOL_ERROR_PARSE_ERROR;
        return false;
    }
    bool warning(const QXmlParseException &exception)
    {
        printParseException(exception);
        errorstate = PROTOCOL_ERROR_PARSE_ERROR;
        return false;
    }
    QString errorString() const
    {
        switch(errorstate)
        {
            case PROTOCOL_ERROR_NOERROR:
                return ("No error (You should not see this).");
            case PROTOCOL_ERROR_OPEN_ERROR:
                return ("Unable to open the network protocol database XML file.");
            case PROTOCOL_ERROR_PARSE_ERROR:
                {
                    std::string message( "XML Parse error:\n");
                    BOOST_FOREACH( std::string const & s, parseerror )
                        message += s;
                    return message.c_str();
                }
            case PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND:
                return ("'protocol' tag requires a 'name' attribute, but none was found.");
            case PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN:
                return ("'threat' attribute has an unrecognised value.");
            case PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN:
                return ("'falsepos' attribute has an unrecognised value.");
            case PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND:
                return ("'port' element requires a 'portnum' attribute, but none was found.");
            case PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT:
                return ("'portnum' attribute is not a valid unsigned integer.");
            case PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND:
                return ("'portrange' element requires a 'start' attribute, but none was found.");
            case PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT:
                return ("'start' attribute is not a valid unsigned integer.");
            case PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND:
                return ("'portrange' element requires a 'end' attribute, but none was found.");
            case PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT:
                return ("'end' attribute is not a valid unsigned integer.");
            case PROTOCOL_ERROR_PORTRANGE_END_LESS_START:
                return ("'start' attribute must be greater than 'end' attribute.");
            case PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN:
            case PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN:
            case PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN:
            case PROTOCOL_ERROR_IP_SOURCE_UNKNOWN:
                return ("'source' attribute must be one of 'client', 'server' or 'host'.");
            case PROTOCOL_ERROR_TCP_DEST_UNKNOWN:
            case PROTOCOL_ERROR_UDP_DEST_UNKNOWN:
            case PROTOCOL_ERROR_ICMP_DEST_UNKNOWN:
            case PROTOCOL_ERROR_IP_DEST_UNKNOWN:
                return ("'dest' attribute must be one of 'client', 'server' or 'host'.");
            case PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND:
                return ("'type' element requires a 'value' attribute, but none was found.");
            case PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT:
                return ("'value' attribute is not a valid unsigned integer.");
            case PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT:
                return ("'code' attribute is not a valid unsigned integer.");
            case PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN:
                return ("'class' attribute has an unrecognised value.");
            case PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND:
                return ("'ip' element requires a 'protocol' attribute, but none was found.");
            case PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT:
                return ("'protocol' attribute is not a valid unsigned integer.");
            case PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE:
                return ("'protocol' attribute is out of range. (Must be 8 bit).");

            default:
                return ("Unknown error. (You should never see this).");
        }
    }
    void printParseException(const QXmlParseException &exception)
    {
        std::stringstream ss;
        ss << "Line: "   << exception.lineNumber()   << ", "
           << "Column: " << exception.columnNumber() << " "  << exception.systemId().toStdString() << ", "
           << exception.publicId().toStdString()     << ", " << exception.message().toStdString()  << std::endl;
        parseerror.push_back( ss.str() );
    }

    void doNetuseLanguage(const QXmlAttributes &atts)
    {
        int i;
        std::string tmp;

        loaddescription = false;
        i = atts.index(protocolnamespace.c_str(),langattr.c_str());
        if(i!=-1)
            tmp = atts.value(i).toStdString();
        else
            tmp = "en";
        if(currentnetuse.descriptionlanguage.empty())
        {
            loaddescription = true;
            currentnetuse.descriptionlanguage = tmp;
        }
    }

    ProtocolEntry & lookup( std::string const & name )
    {
        std::vector< ProtocolEntry >::iterator pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::name, boost::phoenix::arg_names::arg1) == name );
        if ( pit == protocolDataBase.end() )
        {
            pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::longname, boost::phoenix::arg_names::arg1) == name );
            if ( pit == protocolDataBase.end() )
            {
                std::cout << "Didn't protocol database: " << name << std::endl;
                throw std::string("Zone not found 4");
            }
        }
        return *pit;
    }

    ProtocolEntry const & lookup( std::string const & name ) const
    {
        std::vector< ProtocolEntry >::const_iterator pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::name, boost::phoenix::arg_names::arg1) == name );
        if ( pit == protocolDataBase.end() )
        {
            pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::longname, boost::phoenix::arg_names::arg1) == name );
            if ( pit == protocolDataBase.end() )
            {
                std::cout << "Didn't protocol database: " << name << std::endl;
                throw std::string("Zone not found 5");
            }
        }
        return *pit;
    }

    template <typename func>
    void ApplyToDB(func & f)
    {
        BOOST_FOREACH(ProtocolEntry & i, protocolDataBase)
            f(i);
    }

    template<class T>
    void ApplyToNthInClass(T & func, int i, std::string c)
    {
        int n = 0;
        BOOST_FOREACH(ProtocolEntry & ent, protocolDataBase)
        {
            if(ent.classification == c)
            {
                if(n == i)
                {
                    func(ent);
                    break;
                }
                n++;
            }
        }
        if (n != i)
            std::cerr << "Index too great" << std::endl;
    }

/*this shouldn't be referenced anymore
    std::vector< ProtocolEntry > const & getProtocolDataBase() const
    {
        return protocolDataBase;
    }
*/
    void addProtocolEntry( ProtocolEntry const & pe )
    {
        protocolDataBase.push_back( pe );
    }

    void UserDefinedProtocol(std::string name, uchar udptype, uint startp, uint endp, bool bi)
    {
        ProtocolEntry entry( name );
        entry.longname = name;
        entry.classification = "User Defined";
        ProtocolNetUse netuse;
        netuse.addDest(ProtocolNetUseDetail(PORTRANGE_RANGE, startp, endp));
        netuse.setType(udptype);
        netuse.setBidirectional(bi);
        entry.addNetwork(netuse);
        addProtocolEntry(entry);
    }

    void deleteProtocolEntry( std::string const & name )
    {
        std::vector< ProtocolEntry >::iterator pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::name, boost::phoenix::arg_names::arg1) == name );
        if ( pit == protocolDataBase.end() )
        {
            pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::longname, boost::phoenix::arg_names::arg1) == name );
            if ( pit == protocolDataBase.end() )
            {
                std::cout << "Couldn't find protocol: " << name << std::endl;
                throw std::string("Protocol not found");
            }
        }
        protocolDataBase.erase(pit);
    }
};

