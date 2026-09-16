rule NimBlackout
{
    meta:
        description = "Detection patterns for the tool 'NimBlackout' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimBlackout"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/NimBlackout" nocase ascii wide
                        $string2 = "/NimBlackout" nocase ascii wide
                        $string3 = "/NimBlackout" nocase ascii wide
                        $string4 = "/NimBlackout"

    condition:
        any of them
}