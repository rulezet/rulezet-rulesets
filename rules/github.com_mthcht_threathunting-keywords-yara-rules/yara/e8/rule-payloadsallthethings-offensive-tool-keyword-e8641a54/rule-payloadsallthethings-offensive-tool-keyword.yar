rule rule_PayloadsAllTheThings_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PayloadsAllTheThings' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PayloadsAllTheThings"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PayloadsAllTheThings_offensive_tool_keyword = "PayloadsAllTheThings" nocase ascii wide

    condition:
        any of them
}