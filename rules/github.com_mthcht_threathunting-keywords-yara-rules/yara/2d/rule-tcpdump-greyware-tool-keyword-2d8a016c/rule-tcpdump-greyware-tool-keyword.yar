rule rule_tcpdump_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tcpdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tcpdump"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tcpdump_greyware_tool_keyword = "tcpdump "

    condition:
        any of them
}