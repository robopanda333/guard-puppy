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
#include <boost/foreach.hpp>


#include <QXmlDefaultHandler>

using std::vector;
using std::string;

//! Holds all Protocols in a nice container
/*!
 * Has all the accessors and modifiers for a Protocol and it's members.
 */
class ProtocolDB
{
    vector<ProtocolEntry> pdb;

//!<Before we could only add 'existant' entries
//!< meaning that the client needed to know about
//!< what an entry was in detail.
//!< They really shouldn't
    void addProtocolEntry( string name );


//!<Deletes an entry from the database by name.
//!<If (there shouldn't be) there is more than one entry with the same name, it deletes the first.
    void deleteProtocolEntry( string name );

//!Creates and adds a protocol entry.
    void addProtocolEntry(string name, uchar type=ProtocolEntry::RANGE, uint_16 startport=0, uint_16 endport=0, bool bi=true);
    template <typename func>
    void ApplyToDB( func & f );           //!<Applies the functor f to all members of the database
    template <typename func>
    void ApplyToClass(func & f, string s);//!<Applies the functor f to all members of classification s in the database

}
