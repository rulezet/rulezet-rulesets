rule rule_NimBlackout_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NimBlackout' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimBlackout"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NimBlackout_offensive_tool_keyword = "/NimBlackout" nocase ascii wide
                        $string2_NimBlackout_offensive_tool_keyword = "/NimBlackout" nocase ascii wide
                        $string3_NimBlackout_offensive_tool_keyword = "/NimBlackout" nocase ascii wide
                        $string4_NimBlackout_offensive_tool_keyword = "/NimBlackout"

    condition:
        any of them
}