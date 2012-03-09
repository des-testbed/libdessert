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
EXTPING = Proto("dessert_ext_ping", "DESSERT_EXT_PING")

-- Create the protocol fields
local f = EXTPING.fields
f.ext_ping_msg = ProtoField.string("dessert.ext.ping.msg", "Message")

-- The dissector function
function EXTPING.dissector(buffer, pinfo, tree)
    -- print("\t\t\t\tParsing Ping extension")
    pinfo.cols.protocol = "DESSERT_EXT_PING"
    
    local subtree = tree:add(EXTPING, buffer,"Extension Data")
    local ext_ping_msg = buffer(0, buffer:len())
    subtree:add(f.ext_ping_msg, ext_ping_msg)
    _G.g_offset = buffer:len()
--    return buffer:len()
end



-- Create a new dissector
EXTPONG = Proto("dessert_ext_pong", "DESSERT_EXT_PONG")

-- Create the protocol fields
local f = EXTPONG.fields
f.ext_pong_msg = ProtoField.string("dessert.ext.pong.msg", "Message")

-- The dissector function
function EXTPONG.dissector(buffer, pinfo, tree)
    -- print("\t\t\t\tParsing Pong extension")
    pinfo.cols.protocol = "DESSERT_EXT_PING"
    
    local subtree = tree:add(EXTPONG, buffer,"Extension Data")
    local ext_pong_msg = buffer(0, buffer:len())
    subtree:add(f.ext_pong_msg, ext_pong_msg)
    _G.g_offset = buffer:len()
--    return buffer:len()
end

_G.dessert_register_ext_dissector(0x04 ,"DESSERT_EXT_PING", EXTPING)
_G.dessert_register_ext_dissector(0x05 ,"DESSERT_EXT_PONG", EXTPONG)
