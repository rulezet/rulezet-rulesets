rule LAPSToolkit
{
    meta:
        description = "Detection patterns for the tool 'LAPSToolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSToolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sLAPSToolkit\.ps1/ nocase ascii wide
                        $string2 = /\/LAPSToolkit\.git/ nocase ascii wide
                        $string3 = /\/LAPSToolkit\.ps1/ nocase ascii wide
                        $string4 = /\\LAPSToolkit\.ps1/ nocase ascii wide
                        $string5 = "cd05b7676886e560400643e3852e64483cee95f4741ec8a930c7b1f68479835a" nocase ascii wide
                        $string6 = "Find-LAPSDelegatedGroups " nocase ascii wide
                        $string7 = "LAPSToolkit" nocase ascii wide
                        $string8 = /LAPSToolkit\.ps1/ nocase ascii wide
                        $string9 = "leoloobeek/LAPSToolkit" nocase ascii wide

    condition:
        any of them
}