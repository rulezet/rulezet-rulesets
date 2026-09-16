rule rule_nbtstat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nbtstat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nbtstat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nbtstat_greyware_tool_keyword = "nbtstat -n" nocase ascii wide

    condition:
        any of them
}