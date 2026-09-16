rule rule_tcpreplay_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tcpreplay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tcpreplay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tcpreplay_offensive_tool_keyword = "tcpreplay" nocase ascii wide

    condition:
        any of them
}