rule rule_DesertNut_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DesertNut' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DesertNut"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DesertNut_offensive_tool_keyword = /DesertNut\.csproj/ nocase ascii wide
                        $string2_DesertNut_offensive_tool_keyword = /DesertNut\.exe/ nocase ascii wide
                        $string3_DesertNut_offensive_tool_keyword = /DesertNut\.sln/ nocase ascii wide
                        $string4_DesertNut_offensive_tool_keyword = /DesertNut_h\.cs/ nocase ascii wide

    condition:
        any of them
}