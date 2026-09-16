rule rule_Commander_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Commander' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Commander"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Commander_offensive_tool_keyword = /\sc2_server\.py/ nocase ascii wide
                        $string2_Commander_offensive_tool_keyword = /\/c2_server\.py/ nocase ascii wide
                        $string3_Commander_offensive_tool_keyword = /\\c2_server\.py/ nocase ascii wide
                        $string4_Commander_offensive_tool_keyword = /c2_server\.py\s/ nocase ascii wide
                        $string5_Commander_offensive_tool_keyword = "c2-sessions ping" nocase ascii wide
                        $string6_Commander_offensive_tool_keyword = "c2-sessions quit" nocase ascii wide
                        $string7_Commander_offensive_tool_keyword = "cbe60ddb0c22d6a5743901dd06d855958a68a90ab0820665acd1e7b53f0a9c71" nocase ascii wide
                        $string8_Commander_offensive_tool_keyword = /https\:\/\/127\.0\.0\.1\:5000\/register/ nocase ascii wide
                        $string9_Commander_offensive_tool_keyword = /https\:\/\/127\.0\.0\.1\:5000\/results\// nocase ascii wide
                        $string10_Commander_offensive_tool_keyword = /https\:\/\/127\.0\.0\.1\:5000\/tasks\// nocase ascii wide
                        $string11_Commander_offensive_tool_keyword = "voukatas/Commander" nocase ascii wide

    condition:
        any of them
}