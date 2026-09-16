rule VirtualShield_VPN
{
    meta:
        description = "Detection patterns for the tool 'VirtualShield VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VirtualShield VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "aojlhgbkmkahabcmcpifbolnoichfeep" nocase ascii wide

    condition:
        any of them
}