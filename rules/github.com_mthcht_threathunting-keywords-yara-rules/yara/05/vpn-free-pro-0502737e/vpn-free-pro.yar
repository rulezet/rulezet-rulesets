rule VPN_free_pro
{
    meta:
        description = "Detection patterns for the tool 'VPN-free.pro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN-free.pro"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bibjcjfmgapbfoljiojpipaooddpkpai" nocase ascii wide

    condition:
        any of them
}