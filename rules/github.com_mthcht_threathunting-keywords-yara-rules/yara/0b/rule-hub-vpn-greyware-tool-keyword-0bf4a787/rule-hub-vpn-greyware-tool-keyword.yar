rule rule_Hub_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hub VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hub VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Hub_VPN_greyware_tool_keyword = "lneaocagcijjdpkcabeanfpdbmapcjjg" nocase ascii wide

    condition:
        any of them
}