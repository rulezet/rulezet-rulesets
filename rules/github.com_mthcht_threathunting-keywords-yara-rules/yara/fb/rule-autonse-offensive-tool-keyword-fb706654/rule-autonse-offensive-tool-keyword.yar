rule rule_autonse_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'autonse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autonse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_autonse_offensive_tool_keyword = "AutoNSE" nocase ascii wide

    condition:
        any of them
}