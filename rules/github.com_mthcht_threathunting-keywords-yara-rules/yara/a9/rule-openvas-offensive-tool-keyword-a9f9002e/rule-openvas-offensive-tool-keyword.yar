rule rule_openvas_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'openvas' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openvas"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_openvas_offensive_tool_keyword = "OpenVAS"

    condition:
        any of them
}