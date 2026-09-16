rule ntpescape
{
    meta:
        description = "Detection patterns for the tool 'ntpescape' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntpescape"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\|\s\.\/send\s\-d\s.{0,1000}\:123\s\-tM\s0\s\-tm\s0/
                        $string2 = /\.\/recv\s\-d\s\:50001/
                        $string3 = /\.\/send\s\-d\s.{0,1000}\:123\s\-f\s/
                        $string4 = /\/ntpescape\.git/ nocase ascii wide
                        $string5 = "evallen/ntpescape" nocase ascii wide
                        $string6 = /ntpescape.{0,1000}recv/ nocase ascii wide
                        $string7 = /ntpescape.{0,1000}send/ nocase ascii wide
                        $string8 = /ntpescape\-master\./ nocase ascii wide
                        $string9 = /sudo\s\.\/recv\s\-f\s/

    condition:
        any of them
}