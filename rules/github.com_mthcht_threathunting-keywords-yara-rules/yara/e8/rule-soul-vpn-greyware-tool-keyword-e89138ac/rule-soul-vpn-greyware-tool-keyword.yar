rule rule_Soul_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Soul VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Soul VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Soul_VPN_greyware_tool_keyword = "apcfdffemoinopelidncddjbhkiblecc" nocase ascii wide

    condition:
        any of them
}