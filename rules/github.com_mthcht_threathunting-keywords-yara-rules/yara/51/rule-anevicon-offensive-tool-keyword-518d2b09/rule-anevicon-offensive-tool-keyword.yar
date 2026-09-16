rule rule_Anevicon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Anevicon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Anevicon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Anevicon_offensive_tool_keyword = "Anevicon" nocase ascii wide

    condition:
        any of them
}