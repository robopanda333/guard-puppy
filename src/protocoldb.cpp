
#include <netinet/in.h>
#include <vector>
#include <string>
#include <boost/foreach.hpp>

#include "protocoldb.h"


std::vector<uint8_t> ProtocolEntry::getTypes() const
{
    std::vector<uint8_t> temp;
    BOOST_FOREACH(ProtocolEntry::ProtocolNet const & n, networks)
        temp.push_back(n.netType);
    return temp;
}
std::vector<std::string> ProtocolEntry::getDescriptions() const
{
    std::vector<std::string> temp;
    BOOST_FOREACH(ProtocolEntry::ProtocolNet const & n, networks)
        temp.push_back(n.description);
    return temp;
}
//Returns all the bidirectional details of the protocol. This is only ever used when UDP.
std::vector<bool> ProtocolEntry::getBidirectionals() const
{
    std::vector<bool> temp;
    BOOST_FOREACH(ProtocolEntry::ProtocolNet const & n, networks)
        temp.push_back((n.netType==IPPROTO_UDP?n.bidirectional:true));
    return temp;
}
std::vector<uint16_t> ProtocolEntry::getStartPorts(bool DEST) const
{
    std::vector<uint16_t> temp;
    BOOST_FOREACH(ProtocolEntry::ProtocolNet const & n, networks)
        temp.push_back((DEST?(n.destRange):(n.sourceRange)).start);
    return temp;
}
std::vector<uint16_t> ProtocolEntry::getEndPorts(bool DEST) const
{
    std::vector<uint16_t> temp;
    BOOST_FOREACH(ProtocolEntry::ProtocolNet const & n, networks)
        temp.push_back((DEST?(n.destRange):(n.sourceRange)).end);
    return temp;
}
