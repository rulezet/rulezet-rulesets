rule rule_Lovely_Potato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lovely-Potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lovely-Potato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Lovely_Potato_offensive_tool_keyword = "Lovely-Potato" nocase ascii wide

    condition:
        any of them
}