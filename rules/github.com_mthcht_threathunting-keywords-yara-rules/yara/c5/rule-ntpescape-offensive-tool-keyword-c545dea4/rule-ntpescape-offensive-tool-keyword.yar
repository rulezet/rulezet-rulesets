rule rule_ntpescape_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntpescape' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntpescape"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ntpescape_offensive_tool_keyword = /\s\|\s\.\/send\s\-d\s.{0,1000}\:123\s\-tM\s0\s\-tm\s0/
                        $string2_ntpescape_offensive_tool_keyword = /\.\/recv\s\-d\s\:50001/
                        $string3_ntpescape_offensive_tool_keyword = /\.\/send\s\-d\s.{0,1000}\:123\s\-f\s/
                        $string4_ntpescape_offensive_tool_keyword = /\/ntpescape\.git/ nocase ascii wide
                        $string5_ntpescape_offensive_tool_keyword = "evallen/ntpescape" nocase ascii wide
                        $string6_ntpescape_offensive_tool_keyword = /ntpescape.{0,1000}recv/ nocase ascii wide
                        $string7_ntpescape_offensive_tool_keyword = /ntpescape.{0,1000}send/ nocase ascii wide
                        $string8_ntpescape_offensive_tool_keyword = /ntpescape\-master\./ nocase ascii wide
                        $string9_ntpescape_offensive_tool_keyword = /sudo\s\.\/recv\s\-f\s/

    condition:
        any of them
}