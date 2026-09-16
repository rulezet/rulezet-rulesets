rule rule_LyncSniper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LyncSniper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LyncSniper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LyncSniper_offensive_tool_keyword = "LyncSniper" nocase ascii wide

    condition:
        any of them
}