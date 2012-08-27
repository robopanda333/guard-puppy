#include <iostream>
#include <string>
#include <boost/regex.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>

#include "zone.h"
#include "zoneImportStrategy.h"



/*!
 *This class handles importing a zone list in P2P format
#we ignore stuff
hostname:255.0.123.222-255.12.1.132 #GOOD
hostname:321.0.259.0-321.1.0.0 #BAD
hostname:123.0.0.12-123.0.0.1 #BAD
 *it will be nessicary to convert ip ranges into masked ip addresses.
 *there is no support for adding a host name from this format, because the format
 *does not specify a way of doing that, and i don't want to modify the existing standard format
 */
void ZoneImportP2P::Import(std::istream & in, Zone & zone) const
{
    std::string tmp;
    std::getline( in, tmp );
    boost::regex const IPaddresses("(\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b)-(\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b)");
    while(in)
    {
        boost::smatch m;
        boost::regex_search(tmp, m, IPaddresses);
        //std::cerr << "Found: " << m[0] << ", on the line: " << tmp << std::endl;
        if(m.size() == 3)
        {
            RangeFinder finder;
            if( finder.fromString(m[1], m[2]) )
                for(uint i(0); i < finder.size(); i++)
                    zone.addMemberMachine(IPRange(finder.toStdStr(i)));
        }
        std::getline( in, tmp );
    }
}



