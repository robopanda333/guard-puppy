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
//#include <netinet/tcp.h>

#include <vector>
#include <string>
//#include <iostream>
#include <boost/foreach.hpp>

class ProtocolEntry::PortRange


class ProtocolEntry::ProtocolNetUse
{
    Role sourceRole;
    PortRange sourceRange;
    Role destRole;
    PortRange destRange;
    uint8_t protocolType
public:
//!the Roles a destination or source can play
/*!
 *In guarddog this was refered to as an Entity, i feel that
 *Role is a bit better but maybe not.
 */
enum Role { SERVER, CLIENT };

    void setSourceRole( Role );
    void setDestRole( Role );

};


//! Holds all information relavant to a single Protocol
/*!
 *Contains all the information, and accessors for information relavant to a Protocol.
 * All helper classes, and structs, will be accessed through this class.
 * There is no reason for any thing but this class to know about what lies beneath.
 */
class ProtocolEntry
{
//just to make things tidier
using std::string;

    class ProtocolNetUse;
    class PortRange;

    string name;//!<Holds the name of the Protocol
    string longName;//!<Holds the long name. This can be viewed as a short description. For UDPs the name and long name are the same.
    string longNameLanguage;//!<The language that the long name is in.
    string description;//!<Holds the description of the protocol. What programs use it, and what not.
    string descriptionLanguage;//!<The language the description is in. I don't know why this and the longnamelanguage would be different.
    string classification;//!<To what type the protocol belongs. It may be benifitial to make this a list of strings, so there can be more than one.

    std::vector<ProtocolNet> source;
    std::vector<ProtocolNet> dest;

    Score threat;//<!The threat level of a protocol, LOW, MEDIUM, or HIGH.
    Score falsepos;//<!no idea. Figure this one out.

    std::map<string, string> pragma;//!<Holds certian metadata used when generating iptables
public:
    //!The valid Score values.
    enum Score { UNKNOWN, LOW, MEDIUM, HIGH };
    //!The valid Range types.
    enum RangeType { RANGE, ANY, PRIVILEGED, NONPRIVILIGED, DYNAMIC };
};



//! Holds all Protocols in a nice container
/*!
 * Has all the accessors and modifiers for a Protocol and it's members.
 * Unlike the guarddog version of this class, we will not parse XML here. The Firewall manager will handle parseing the XML.
 */
class ProtocolDB
{
//just to make things tidier
using std::string;

    std::vector<ProtocolEntry> pdb;//!<Vector which holds all the entrys in the database

public:

    //!Adds an Entry by name.
    //!The networks of the Protocol are constructed empty
    //!Throws "ProtocolEntry *name* Already exists!"
    void addProtocolEntry(string name);
    
    //!Adds an Entry by data.
    //!Adds a default network source and destination (the source being completly open, the destination being specified)
    void addProtocolEntry(string name , ProtocolEntry::RangeType rangeType, in_port_t startport = 0,
                             in_port_t endport = 0, uint8_t portType = IPPROTO_TCP, bool bi = true);//in_port_t is an alias for uint16_t and is the "prefered" type for portnumbers
    //!Deletes an entry from the database by name.
    //!If (there shouldn't be) there is more than one entry with the same name, it deletes the first.
    void deleteProtocolEntry( string name );

    //!Applies the functor f to all members of the database
    template <typename func>
    void applyToDB( func & f );

    //!Applies the functor f to all members of classification s in the database
    template <typename func>
    void applyToClass(func & f, string s);

    //!Finds and returns a reference to a Protocol Entry by name
    ProtocolEntry & lookup( string const & name );
    //!Finds and returns a const reference to a Protocol Entry by name
    ProtocolEntry const & lookup( string const & name ) const;
};




















