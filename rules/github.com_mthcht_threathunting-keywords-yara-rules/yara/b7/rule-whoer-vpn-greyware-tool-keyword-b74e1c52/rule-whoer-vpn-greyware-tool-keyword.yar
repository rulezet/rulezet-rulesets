rule rule_Whoer_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Whoer VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Whoer VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Whoer_VPN_greyware_tool_keyword = "cgojmfochfikphincbhokimmmjenhhgk" nocase ascii wide

    condition:
        any of them
}