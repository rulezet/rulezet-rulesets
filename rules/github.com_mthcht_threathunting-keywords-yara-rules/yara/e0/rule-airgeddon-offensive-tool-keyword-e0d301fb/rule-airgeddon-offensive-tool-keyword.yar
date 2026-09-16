rule rule_Airgeddon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Airgeddon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Airgeddon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Airgeddon_offensive_tool_keyword = "Airgeddon"

    condition:
        any of them
}