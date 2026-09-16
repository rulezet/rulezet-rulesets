rule tcpdump
{
    meta:
        description = "Detection patterns for the tool 'tcpdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tcpdump"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "tcpdump "

    condition:
        any of them
}