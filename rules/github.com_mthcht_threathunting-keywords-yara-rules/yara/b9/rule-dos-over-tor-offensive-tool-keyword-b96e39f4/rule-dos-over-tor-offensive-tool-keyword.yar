rule rule_dos_over_tor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dos-over-tor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dos-over-tor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dos_over_tor_offensive_tool_keyword = "dos-over-tor" nocase ascii wide

    condition:
        any of them
}