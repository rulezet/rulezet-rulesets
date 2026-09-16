rule rule_wifiphisher_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wifiphisher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifiphisher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wifiphisher_offensive_tool_keyword = "wifiphisher" nocase ascii wide

    condition:
        any of them
}