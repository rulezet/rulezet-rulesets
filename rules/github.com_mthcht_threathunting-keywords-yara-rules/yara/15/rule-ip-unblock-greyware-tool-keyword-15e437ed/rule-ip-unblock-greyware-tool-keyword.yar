rule rule_IP_Unblock_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IP Unblock' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IP Unblock"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_IP_Unblock_greyware_tool_keyword = "lochiccbgeohimldjooaakjllnafhaid" nocase ascii wide

    condition:
        any of them
}