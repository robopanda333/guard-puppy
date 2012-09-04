#pragma once
#include <iostream>
#include <string>
#include <bitset>
#include <boost/regex.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>

class Zone;

class RangeFinder
{
    std::vector<uint32_t> address;
    std::vector<uint8_t> mask;

    //ip 0 is a special address, so we assume no one will input it.
    uint32_t IpStringToInt(std::string str)
    {
        boost::regex const test("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
        boost::smatch s;
        boost::regex_search(str, s, test);
        uint32_t ret(0);
        uint8_t temp(0);
        if(s.size() != 5)//make sure there are enough
            return 0;
        for(size_t i(0); i < 4; ++i)
        {
            try{ temp = boost::numeric_cast<uint8_t>( boost::lexical_cast<uint>(s[i+1]) ); }
            catch(...){ return 0; }//the numeric cast does our range checking for us. a lex cast unable to do it for us.
            ret |= temp << (24 - 8*i);
        }
        return ret;
    }

    enum states
    {//cur_prev
        s0_0, //for lower bound:if empty move, else add child 1, move  for upper bound:move up
        s0_1, //for lower bound:move up                                for upper bound:if first add self, else add child 0
        s1_0, //for lower bound:if first add self, else add child 1    for upper bound:move up
        s1_1, //for lower bound:move up                                for upper bound:if empty move, else add child 1
        s0,
        s1
    };

    bool Factor( uint32_t lower, uint32_t upper )
    {
        if(lower == upper) //our "range" is one ip
        {
            address.push_back(lower);
            mask.push_back(32);
            return true;
        }
        std::bitset<32> temp(lower ^ upper);
        uint8_t pos(31);
        while(! (temp.to_ulong() & (1 << pos)) ) pos--;

        if(!PopulateLower(pos, lower))
            return false;
        if(!PopulateUpper(pos, upper))
            return false;
        return address.size() == mask.size();
    }

    bool PopulateUpper(uint8_t pos, uint32_t addr)
    {
        states s_state( s1 );
        bool found( false );

        if( !(addr & 1) )
        {
            address.push_back(addr);
            mask.push_back( 32 );
            s_state = s0;
            found = true;
        }
        else
            addr &= ~1;

        for(int i(1); i <= pos+1; i++)
        {
            uint32_t bitmask = 1<<i;
            switch(s_state)
            {
                case s0_0: case s0_1: case s0:
                    if( addr & bitmask )
                        s_state = s1_0;
                    else
                        s_state = s0_0;
                    break;
                case s1_0: case s1_1: case s1:
                    if( addr & bitmask )
                        s_state = s1_1;
                    else
                        s_state = s0_1;
                    break;
                default: return false; //bail out.
            }
            addr &= ~bitmask;
            switch(s_state)
            {
                case s0_0:case s1_0: break;
                case s1_1:
                    if(found)
                    {
                        address.push_back(addr | bitmask);
                        mask.push_back(33-i);
                    }
                    break;
                case s0_1:
                    if(found)
                    {
                        address.push_back(addr);
                        mask.push_back(33-i);
                    }
                    else
                    {
                        address.push_back(addr);
                        mask.push_back(32-i);
                        found = true;
                    }
                    break;
                default: return false; //bail out.
            }
        }
        return true;
    }

    bool PopulateLower(uint8_t pos, uint32_t addr)
    {
        states s_state( s0 );
        bool found( false );
        if(addr & 1)
        {
            address.push_back(addr);
            mask.push_back( 32 );
            addr &= ~1;
            s_state = s1;
            found = true;
        }
        for(int i(1); i <= pos+1; i++)
        {
            uint32_t bitmask = 1<<i;
            switch(s_state)
            {
                case s0_0: case s0_1: case s0:
                    if( addr & bitmask )
                        s_state = s1_0;
                    else
                        s_state = s0_0;
                    break;
                case s1_0: case s1_1: case s1:
                    if( addr & bitmask )
                        s_state = s1_1;
                    else
                        s_state = s0_1;
                    break;
                default: return false; //bail out.
            }
            addr &= ~bitmask;
            switch(s_state)
            {
                case s1_1:case s0_1: break;
                case s0_0:
                    if(found)
                    {
                        address.push_back( (addr | (bitmask>>1)) );
                        mask.push_back(33-i);
                    }
                    break;
                case s1_0:
                    if(found)
                    {
                        address.push_back( (addr | bitmask ) | (bitmask>>1) );
                        mask.push_back(33-i);
                    }
                    else
                    {
                        address.push_back( (addr | bitmask) );
                        mask.push_back(32-i);
                        found = true;
                    }
                    break;
                default: return false; //bail out.
            }
        }
        return true;
    }
public:

    bool fromString(std::string const & lower, std::string const & upper)
    {
        uint32_t start( IpStringToInt(lower) ), end( IpStringToInt(upper) );
        if( !(start && end) )
            return false;
        if( start > end )
            return false;
        return Factor(start, end);
    }

    bool fromInts(uint32_t lower, uint32_t upper)
    {
        if( !(lower && upper) )
            return false;
        if( lower > upper )
            return false;
        return Factor(lower, upper);
    }
    size_t size()
    {
        return address.size();
    }
    std::string toStdStr(size_t i)
    {
        if(i >= address.size() ) return "";
        std::stringstream s;
            s << ( (address[i]<< 0)>>24 ) << "."
              << ( (address[i]<< 8)>>24 ) << "."
              << ( (address[i]<<16)>>24 ) << "."
              << ( (address[i]<<24)>>24 ) << "/"
              << (int)mask[i];
        return s.str();
    }

};


class ZoneImportABCstrategy //our strategy interface
{

public:
    virtual ~ZoneImportABCstrategy() { }
    virtual void Import(std::istream & in, Zone & zone) const = 0;
};

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
class ZoneImportP2P: public ZoneImportABCstrategy
{
public:
    ~ZoneImportP2P() { }
    void Import(std::istream & in, Zone & zone) const;
};

/*void ZoneImport(std::istream & i, Zone & zone, ZoneImportABCstrategy & strategy)
{
    //we have no way of knowing how the stream will work so we need to take the callers
    //word that it will be the correct type of stream
}*/


