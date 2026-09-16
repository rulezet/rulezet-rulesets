rule rule_BeeLogger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BeeLogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeeLogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BeeLogger_offensive_tool_keyword = "Beelogger" nocase ascii wide

    condition:
        any of them
}