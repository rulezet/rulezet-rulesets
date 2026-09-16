rule rule_LAPSToolkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LAPSToolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSToolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LAPSToolkit_offensive_tool_keyword = /\sLAPSToolkit\.ps1/ nocase ascii wide
                        $string2_LAPSToolkit_offensive_tool_keyword = /\/LAPSToolkit\.git/ nocase ascii wide
                        $string3_LAPSToolkit_offensive_tool_keyword = /\/LAPSToolkit\.ps1/ nocase ascii wide
                        $string4_LAPSToolkit_offensive_tool_keyword = /\\LAPSToolkit\.ps1/ nocase ascii wide
                        $string5_LAPSToolkit_offensive_tool_keyword = "cd05b7676886e560400643e3852e64483cee95f4741ec8a930c7b1f68479835a" nocase ascii wide
                        $string6_LAPSToolkit_offensive_tool_keyword = "Find-LAPSDelegatedGroups " nocase ascii wide
                        $string7_LAPSToolkit_offensive_tool_keyword = "LAPSToolkit" nocase ascii wide
                        $string8_LAPSToolkit_offensive_tool_keyword = /LAPSToolkit\.ps1/ nocase ascii wide
                        $string9_LAPSToolkit_offensive_tool_keyword = "leoloobeek/LAPSToolkit" nocase ascii wide

    condition:
        any of them
}