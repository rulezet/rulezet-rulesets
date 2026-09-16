rule rule_Stifle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Stifle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stifle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Stifle_offensive_tool_keyword = /\\tStifle\.exe/ nocase ascii wide
                        $string2_Stifle_offensive_tool_keyword = "186789b7b7c4973d4f941582a796c3ced5ae7fbc4527cf19040e740d380c4106" nocase ascii wide
                        $string3_Stifle_offensive_tool_keyword = "a507307a4b6e0f6f00e8a3f3330204c124fa5a69cfc03ffd89235c7e4b77f25d" nocase ascii wide
                        $string4_Stifle_offensive_tool_keyword = "EDBAAABC-1214-41C0-8EEE-B61056DE37ED" nocase ascii wide
                        $string5_Stifle_offensive_tool_keyword = "logangoins/Stifle" nocase ascii wide
                        $string6_Stifle_offensive_tool_keyword = /Stifle\.exe\sadd\s\/object\:/ nocase ascii wide
                        $string7_Stifle_offensive_tool_keyword = /Stifle\.exe\sclear\s/ nocase ascii wide

    condition:
        any of them
}