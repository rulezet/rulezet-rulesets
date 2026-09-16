rule rule_Infoga_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Infoga' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Infoga"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Infoga_offensive_tool_keyword = "/Infoga"

    condition:
        any of them
}