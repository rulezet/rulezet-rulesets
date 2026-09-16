rule twittor
{
    meta:
        description = "Detection patterns for the tool 'twittor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "twittor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/twittor\.git/ nocase ascii wide
                        $string2 = "PaulSec/twittor" nocase ascii wide
                        $string3 = /twittor\.py/ nocase ascii wide
                        $string4 = /twittor\-master\.zip/ nocase ascii wide

    condition:
        any of them
}