rule rule_airmon_ng_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'airmon-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "airmon-ng"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_airmon_ng_offensive_tool_keyword = "airmon-ng" nocase ascii wide

    condition:
        any of them
}