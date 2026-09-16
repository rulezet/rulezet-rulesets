rule TunnelBear_VPN
{
    meta:
        description = "Detection patterns for the tool 'TunnelBear VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TunnelBear VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "omdakjcmkglenbhjadbccaookpfjihpa" nocase ascii wide

    condition:
        any of them
}