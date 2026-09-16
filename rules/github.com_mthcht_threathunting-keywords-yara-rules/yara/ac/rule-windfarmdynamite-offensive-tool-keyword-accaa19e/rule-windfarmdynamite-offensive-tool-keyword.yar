rule rule_WindfarmDynamite_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WindfarmDynamite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindfarmDynamite"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WindfarmDynamite_offensive_tool_keyword = /WindfarmDynamite\.cdproj/ nocase ascii wide
                        $string2_WindfarmDynamite_offensive_tool_keyword = /WindfarmDynamite\.exe/ nocase ascii wide
                        $string3_WindfarmDynamite_offensive_tool_keyword = /WindfarmDynamite\.sln/ nocase ascii wide
                        $string4_WindfarmDynamite_offensive_tool_keyword = /WNFarmDynamite_h\.cs/ nocase ascii wide

    condition:
        any of them
}