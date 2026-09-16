rule Free_VPN_for_Chrome
{
    meta:
        description = "Detection patterns for the tool 'Free VPN for Chrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free VPN for Chrome"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "klnkiajpmpkkkgpgbogmcgfjhdoljacg" nocase ascii wide

    condition:
        any of them
}