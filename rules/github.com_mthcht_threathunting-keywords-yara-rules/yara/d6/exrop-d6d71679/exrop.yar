rule Exrop
{
    meta:
        description = "Detection patterns for the tool 'Exrop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Exrop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sExrop\(.{0,1000}\/bin\//
                        $string2 = " import Exrop" nocase ascii wide
                        $string3 = /\/avoid_badchars\.py/ nocase ascii wide
                        $string4 = /\/ChainBuilder\.py/ nocase ascii wide
                        $string5 = "/d4em0n/exrop" nocase ascii wide
                        $string6 = /\/exploit_orw\.py/ nocase ascii wide
                        $string7 = "/rop_emporium" nocase ascii wide
                        $string8 = "from Exrop import " nocase ascii wide
                        $string9 = "from pwn import " nocase ascii wide
                        $string10 = /rop\.find_gadgets/ nocase ascii wide
                        $string11 = /RopChain\.py/ nocase ascii wide

    condition:
        any of them
}