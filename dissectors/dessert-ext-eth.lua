-- ----------------------------------------------------------------------------
-- Copyright 2009, David Gutzmann, Freie Universitaet Berlin (FUB).
-- Copyright 2010, Bastian Blywis, Freie Universitaet Berlin (FUB).
-- All rights reserved.

--These sources were originally developed by David Gutzmann,
--rewritten and extended by Bastian Blywis
--at Freie Universitaet Berlin (http://www.fu-berlin.de/),
--Computer Systems and Telematics / Distributed, embedded Systems (DES) group
--(http://cst.mi.fu-berlin.de, http://www.des-testbed.net)
-- ----------------------------------------------------------------------------
--This program is free software: you can redistribute it and/or modify it under
--the terms of the GNU General Public License as published by the Free Software
--Foundation, either version 3 of the License, or (at your option) any later
--version.

--This program is distributed in the hope that it will be useful, but WITHOUT
--ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
--FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

--You should have received a copy of the GNU General Public License along with
--this program. If not, see http://www.gnu.org/licenses/ .
-- ----------------------------------------------------------------------------
--For further information and questions please use the web site
--       http://www.des-testbed.net
-- ----------------------------------------------------------------------------

-- Create a new dissector
EXTETH = Proto("dessert_ext_eth", "DESSERT_EXT_ETH")

-- Create the protocol fields
local f = EXTETH.fields
-- f.extdata = ProtoField.ether("ext_eth.extdata", "Extension data")
f.ext_eth_dhost = ProtoField.ether("dessert.ext.eth.dhost", "Destination")
f.ext_eth_shost = ProtoField.ether("dessert.ext.eth.shost", "Source")
f.ext_eth_ethertype = ProtoField.uint16("dessert.ext.eth.ethertype", "Type", base.HEX, nil)

-- The dissector function
function EXTETH.dissector (buffer, pinfo, tree)
--     print("\t\t\t\tParsing ETH extension")
    pinfo.cols.protocol = "DESSERT_EXT_ETH"

    local subtree = tree:add(EXTETH, buffer,"Extension Data")
    local offset = 0
    local ext_eth_dhost = buffer(offset, 6)
    offset = offset + 6
    local ext_eth_shost = buffer(offset, 6)
    offset = offset + 6
    local ext_eth_ethertype = buffer(offset, 2)
    offset = offset + 2
    subtree:add(f.ext_eth_dhost, ext_eth_dhost)
    subtree:add(f.ext_eth_shost, ext_eth_shost)
    subtree:add(f.ext_eth_ethertype, ext_eth_ethertype)
    print("\t\t\t\tEthertype is: "..tostring(ext_eth_ethertype))
    _G.g_ethertype = ext_eth_ethertype
	_G.g_offset = offset
    return offset
end

_G.dessert_register_ext_dissector(0x01 ,"DESSERT_EXT_ETH", EXTETH)
