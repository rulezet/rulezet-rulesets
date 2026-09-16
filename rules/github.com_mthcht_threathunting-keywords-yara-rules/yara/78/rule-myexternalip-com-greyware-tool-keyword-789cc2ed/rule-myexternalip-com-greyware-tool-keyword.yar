rule rule_myexternalip_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'myexternalip.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "myexternalip.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_myexternalip_com_greyware_tool_keyword = /https\:\/\/myexternalip\.com\/raw/ nocase ascii wide

    condition:
        any of them
}