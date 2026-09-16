rule rule_Exrop_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Exrop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Exrop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Exrop_offensive_tool_keyword = /\sExrop\(.{0,1000}\/bin\//
                        $string2_Exrop_offensive_tool_keyword = " import Exrop" nocase ascii wide
                        $string3_Exrop_offensive_tool_keyword = /\/avoid_badchars\.py/ nocase ascii wide
                        $string4_Exrop_offensive_tool_keyword = /\/ChainBuilder\.py/ nocase ascii wide
                        $string5_Exrop_offensive_tool_keyword = "/d4em0n/exrop" nocase ascii wide
                        $string6_Exrop_offensive_tool_keyword = /\/exploit_orw\.py/ nocase ascii wide
                        $string7_Exrop_offensive_tool_keyword = "/rop_emporium" nocase ascii wide
                        $string8_Exrop_offensive_tool_keyword = "from Exrop import " nocase ascii wide
                        $string9_Exrop_offensive_tool_keyword = "from pwn import " nocase ascii wide
                        $string10_Exrop_offensive_tool_keyword = /rop\.find_gadgets/ nocase ascii wide
                        $string11_Exrop_offensive_tool_keyword = /RopChain\.py/ nocase ascii wide

    condition:
        any of them
}