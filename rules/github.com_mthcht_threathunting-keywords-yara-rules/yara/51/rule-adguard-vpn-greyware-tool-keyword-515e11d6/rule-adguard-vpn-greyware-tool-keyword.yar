rule rule_AdGuard_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AdGuard VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdGuard VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AdGuard_VPN_greyware_tool_keyword = "hhdobjgopfphlmjbmnpglhfcgppchgje" nocase ascii wide

    condition:
        any of them
}