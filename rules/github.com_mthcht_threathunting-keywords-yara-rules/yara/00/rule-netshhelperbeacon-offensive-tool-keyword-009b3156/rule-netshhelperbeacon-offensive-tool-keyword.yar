rule rule_NetshHelperBeacon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetshHelperBeacon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetshHelperBeacon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NetshHelperBeacon_offensive_tool_keyword = /\/NetshHelperBeacon\.git/ nocase ascii wide
                        $string2_NetshHelperBeacon_offensive_tool_keyword = /\\NetshHelperBeacon\.cpp/ nocase ascii wide
                        $string3_NetshHelperBeacon_offensive_tool_keyword = /\\NetshHelperBeacon\.dll/ nocase ascii wide
                        $string4_NetshHelperBeacon_offensive_tool_keyword = /\\NetshHelperBeacon\.lib/ nocase ascii wide
                        $string5_NetshHelperBeacon_offensive_tool_keyword = /\\NetshHelperBeacon\.log/ nocase ascii wide
                        $string6_NetshHelperBeacon_offensive_tool_keyword = /\\NetshHelperBeacon\.pdb/ nocase ascii wide
                        $string7_NetshHelperBeacon_offensive_tool_keyword = /\\NetshHelperBeacon\\/ nocase ascii wide
                        $string8_NetshHelperBeacon_offensive_tool_keyword = /\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48/ nocase ascii wide
                        $string9_NetshHelperBeacon_offensive_tool_keyword = /\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2\\xf0\\x52\\x57\\x8b\\x52\\x10\\x8b\\x42\\x3c\\x01\\xd0\\x8b\\x40\\x78\\x85\\xc0\\x74\\x4a\\x01\\xd0\\x50\\x8b\\x48\\/ nocase ascii wide
                        $string10_NetshHelperBeacon_offensive_tool_keyword = "3BB0CD58-487C-4FEC-8001-607599477158" nocase ascii wide
                        $string11_NetshHelperBeacon_offensive_tool_keyword = "93b20a7961c9986baf181d1a1635b33b87735f75d046c6dcdd5d412a55832d6f" nocase ascii wide
                        $string12_NetshHelperBeacon_offensive_tool_keyword = "9ecca3b6c787675d74bbfaa0e3ded77d448a0de4fe51c3c29c07cf3b04b8b71d" nocase ascii wide
                        $string13_NetshHelperBeacon_offensive_tool_keyword = "a84e1abea8327bcede6dfb79b50b36780f2e1cdb8166002d75c070574a83738f" nocase ascii wide
                        $string14_NetshHelperBeacon_offensive_tool_keyword = /NetshHelperBeacon\.exe/ nocase ascii wide
                        $string15_NetshHelperBeacon_offensive_tool_keyword = "outflanknl/NetshHelperBeacon" nocase ascii wide
                        $string16_NetshHelperBeacon_offensive_tool_keyword = "Simple code for creating a DLL for netsh helper DLLs" nocase ascii wide

    condition:
        any of them
}