rule rule_airpwn_ng_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'airpwn-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "airpwn-ng"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_airpwn_ng_offensive_tool_keyword = "airpwn-ng" nocase ascii wide

    condition:
        any of them
}