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

local extension_types = { [0x01] = "DESSERT_EXT_ETH",
                          [0x02] = "DESSERT_EXT_TRACE_REQ",
                          [0x03] = "DESSERT_EXT_TRACE_RPL",
                          [0x04] = "DESSERT_EXT_PING",
                          [0x05] = "DESSERT_EXT_PONG",
                          [0x40] = "DESSERT_EXT_USER"
                         }

dessert_dissector_table = DissectorTable.new("desserttable")

_G.dessert_register_ext_dissector = function(ext_type, ext_name, dissector)
    print("Info: loading extension dissector: "..tostring(ext_name))
    extension_types[ext_type] = ext_name
    dessert_dissector_table:add(ext_type, dissector)
end

dofile("dessert-ext-eth.lua")
dofile("dessert-ext-ping.lua")
dofile("dessert-ext-trace.lua")

-- Create a new dissector
DESSERT = Proto ("dessert", "DES-SERT")

-- Create the protocol fields
local f = DESSERT.fields

f.proto   = ProtoField.string ("dessert.proto"  , "Protocol name")
f.version = ProtoField.uint8  ("dessert.version", "Protocol version")

f.flags   = ProtoField.uint8  ("dessert.flags"  , "Flags" , base.HEX, nil, 0xFF)
f.flags_1 = ProtoField.uint8  ("dessert.flags_1", "Flag 1", base.HEX, nil, 0x01)
f.flags_2 = ProtoField.uint8  ("dessert.flags_2", "Flag 2", base.HEX, nil, 0x02)
f.flags_3 = ProtoField.uint8  ("dessert.flags_3", "Flag 3", base.HEX, nil, 0x04)
f.flags_4 = ProtoField.uint8  ("dessert.flags_4", "Flag 4", base.HEX, nil, 0x08)
f.flags_5 = ProtoField.uint8  ("dessert.sparse" , "DESSERT_FLAG_SPARSE", base.HEX, nil, 0x10,"if not set buffer len is assumed as DESSERT_MAXFRAMELEN + DESSERT_MSGPROCLEN ")
f.flags_6 = ProtoField.uint8  ("dessert.flags_6", "Flag 6", base.HEX, nil, 0x20)
f.flags_7 = ProtoField.uint8  ("dessert.flags_7", "Flag 7", base.HEX, nil, 0x40)
f.flags_8 = ProtoField.uint8  ("dessert.flags_8", "Flag 8", base.HEX, nil, 0x80)

f.u32     = ProtoField.uint32 ("dessert.u32", "u32", base.HEX ,nil)
f.ttl     = ProtoField.uint8  ("dessert.ttl", "ttl", base.DEC ,nil)
f.u8      = ProtoField.uint8  ("dessert.u8", "u8", base.HEX ,nil)
f.u16     = ProtoField.uint16 ("dessert.u16", "u16", base.HEX, nil)

f.hlen    = ProtoField.uint16 ("dessert.hlen", "Header length hlen (incl. layer 2.5)", base.DEC, nil,nil,"header length incl. extensions")
f.plen    = ProtoField.uint16 ("dessert.plen", "Payload length plen", base.DEC, nil)
f.exts    = ProtoField.string ("dessert.exts", "Extensions")

EXTHDR = Proto("dessert_ext", "DESSERT_EXT");
local e = EXTHDR.fields
e.exttype = ProtoField.uint8  ("dessert.ext.type", "Extension type", base.HEX )
e.extlen  = ProtoField.uint8  ("dessert.ext.len", "Extension length (incl. extension header)", base.DEC ,nil,nil, "length of the extension in bytes, including the 2 bytes of the extension header itself")

-- The dissector function
function DESSERT.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "DES-SERT"

    local subtree = tree:add(DESSERT, buffer(),"DES-SERT Protocol Data")
    local offset = 0

    local proto = buffer (offset, 4)
    subtree:add(f.proto, proto)
    offset = offset + 4

    local version= buffer (offset, 1)
    subtree:add(f.version, version)
    offset = offset + 1

    local flags = buffer (offset, 1)
    local flags_field = subtree:add(f.flags, flags)
    flags_field:add(f.flags_1, flags)
    flags_field:add(f.flags_2, flags)
    flags_field:add(f.flags_3, flags)
    flags_field:add(f.flags_4, flags)
    flags_field:add(f.flags_5, flags)
    flags_field:add(f.flags_6, flags)
    flags_field:add(f.flags_7, flags)
    flags_field:add(f.flags_8, flags)
    offset = offset + 1

    local u32 = buffer (offset, 4)
    local ttl = buffer (offset, 1)
    local u8  = buffer (offset+1, 1)
    local u16 = buffer (offset+2, 2)
    local u32_field = subtree:add(f.u32, u32)
    u32_field:add(f.ttl, ttl)
    u32_field:add(f.u8 , u8)
    u32_field:add(f.u16, u16)
    offset = offset + 4

    local hlen = buffer(offset,2)
    subtree:add(f.hlen, hlen)
    offset = offset + 2

    -- because wireshark already dissected the layer 2.5 header at this point
    -- the *real* header length is hlen-14
    local real_hlen = hlen:uint() - 14

    local plen = buffer(offset,2)
    subtree:add(f.plen, plen)
    offset = offset + 2

    extensions = subtree:add(f.exts)

    local extension, exttype, extlen, extdata_real_length, extdata, exttreeitem, dissector
    local ext_count = 0

    while offset < real_hlen do
      ext_count = ext_count +1
      extension = extensions:add(EXTHDR)
      extension:set_generated()

      exttype = buffer(offset, 1)
      extension:add(e.exttype, exttype)
      offset = offset + 1

      extlen = buffer(offset, 1)
      extension:add(e.extlen, extlen)
      offset = offset + 1

      -- extlen includes the 2byte extension header !
      extdata_real_length = extlen:uint() - 2
      extdata = buffer(offset, extdata_real_length)
      local dissector = dessert_dissector_table:get_dissector(exttype:uint())
      if dissector ~= nil then
          dissector:call(extdata:tvb(), pinfo, extension)
		  length_dissected = _G.g_offset
		  ethertype = _G.g_ethertype
          if length_dissected ~= extdata_real_length then
            print("\t\t\tWarning: Sub-Dissector did not consume all bytes!")
          end
      else
          print("\t\t\tWarning: No extension_dissector for ext_type: "..tostring(extension_types[exttype:uint()]))
      end
      offset = offset + extdata_real_length
      -- print("\t\toffset="..tostring(offset)..", hlen="..tostring(real_hlen))
    end

    -- print("\tno more extensions, offset="..tostring(offset))
    -- dissect paylod based on ext_eth ethertype if any
    ethertype = _G.g_ethertype
    if ethertype:uint() ~= 0 then
        local dissector = ethertype_table:get_dissector(ethertype:uint())
        if dissector ~= nil then
            local payload = buffer(offset, plen:uint())
            dissector:call(payload:tvb(), pinfo, tree)
        else
          print("Warning: Payload found but no matching dissector")
        end
    end
    return offset
end

-- load the ethertype table
ethertype_table = DissectorTable.get("ethertype")

-- register DES-SERT protocol to handle ethertype 0x88B5
ethertype_table:add(0x88B5, DESSERT)

print("DES-SERT dissector loaded")
