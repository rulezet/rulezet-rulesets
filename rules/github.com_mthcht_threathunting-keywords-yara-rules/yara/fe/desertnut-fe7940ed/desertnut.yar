rule DesertNut
{
    meta:
        description = "Detection patterns for the tool 'DesertNut' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DesertNut"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /DesertNut\.csproj/ nocase ascii wide
                        $string2 = /DesertNut\.exe/ nocase ascii wide
                        $string3 = /DesertNut\.sln/ nocase ascii wide
                        $string4 = /DesertNut_h\.cs/ nocase ascii wide

    condition:
        any of them
}