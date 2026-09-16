rule rule_twittor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'twittor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "twittor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_twittor_offensive_tool_keyword = /\/twittor\.git/ nocase ascii wide
                        $string2_twittor_offensive_tool_keyword = "PaulSec/twittor" nocase ascii wide
                        $string3_twittor_offensive_tool_keyword = /twittor\.py/ nocase ascii wide
                        $string4_twittor_offensive_tool_keyword = /twittor\-master\.zip/ nocase ascii wide

    condition:
        any of them
}