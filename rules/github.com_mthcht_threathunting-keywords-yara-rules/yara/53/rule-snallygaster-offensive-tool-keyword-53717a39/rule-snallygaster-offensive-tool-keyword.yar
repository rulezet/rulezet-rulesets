rule rule_snallygaster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'snallygaster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snallygaster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_snallygaster_offensive_tool_keyword = "snallygaster" nocase ascii wide

    condition:
        any of them
}