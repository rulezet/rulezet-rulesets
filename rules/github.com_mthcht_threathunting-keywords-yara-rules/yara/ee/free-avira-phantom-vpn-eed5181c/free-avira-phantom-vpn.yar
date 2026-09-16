rule Free_Avira_Phantom_VPN
{
    meta:
        description = "Detection patterns for the tool 'Free Avira Phantom VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Avira Phantom VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "dfkdflfgjdajbhocmfjolpjbebdkcjog" nocase ascii wide

    condition:
        any of them
}