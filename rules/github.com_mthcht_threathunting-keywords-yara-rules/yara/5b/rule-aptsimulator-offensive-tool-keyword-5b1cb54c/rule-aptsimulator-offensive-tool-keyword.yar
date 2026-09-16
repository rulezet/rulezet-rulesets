rule rule_APTSimulator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'APTSimulator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "APTSimulator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_APTSimulator_offensive_tool_keyword = "APTSimulator" nocase ascii wide

    condition:
        any of them
}