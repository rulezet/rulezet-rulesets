rule Commander
{
    meta:
        description = "Detection patterns for the tool 'Commander' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Commander"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sc2_server\.py/ nocase ascii wide
                        $string2 = /\/c2_server\.py/ nocase ascii wide
                        $string3 = /\\c2_server\.py/ nocase ascii wide
                        $string4 = /c2_server\.py\s/ nocase ascii wide
                        $string5 = "c2-sessions ping" nocase ascii wide
                        $string6 = "c2-sessions quit" nocase ascii wide
                        $string7 = "cbe60ddb0c22d6a5743901dd06d855958a68a90ab0820665acd1e7b53f0a9c71" nocase ascii wide
                        $string8 = /https\:\/\/127\.0\.0\.1\:5000\/register/ nocase ascii wide
                        $string9 = /https\:\/\/127\.0\.0\.1\:5000\/results\// nocase ascii wide
                        $string10 = /https\:\/\/127\.0\.0\.1\:5000\/tasks\// nocase ascii wide
                        $string11 = "voukatas/Commander" nocase ascii wide

    condition:
        any of them
}