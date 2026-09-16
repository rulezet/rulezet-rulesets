rule WindfarmDynamite
{
    meta:
        description = "Detection patterns for the tool 'WindfarmDynamite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindfarmDynamite"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /WindfarmDynamite\.cdproj/ nocase ascii wide
                        $string2 = /WindfarmDynamite\.exe/ nocase ascii wide
                        $string3 = /WindfarmDynamite\.sln/ nocase ascii wide
                        $string4 = /WNFarmDynamite_h\.cs/ nocase ascii wide

    condition:
        any of them
}