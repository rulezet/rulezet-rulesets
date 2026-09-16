rule sqlninja
{
    meta:
        description = "Detection patterns for the tool 'sqlninja' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlninja"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "sqlninja" nocase ascii wide

    condition:
        any of them
}