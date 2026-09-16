rule Adblock_Office_VPN_Proxy_Server
{
    meta:
        description = "Detection patterns for the tool 'Adblock Office VPN Proxy Server' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adblock Office VPN Proxy Server"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "lcmammnjlbmlbcaniggmlejfjpjagiia" nocase ascii wide

    condition:
        any of them
}