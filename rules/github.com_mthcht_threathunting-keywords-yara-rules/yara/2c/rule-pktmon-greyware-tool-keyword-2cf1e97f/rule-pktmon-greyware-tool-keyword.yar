rule rule_pktmon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pktmon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pktmon"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pktmon_greyware_tool_keyword = "pktmon start" nocase ascii wide

    condition:
        any of them
}