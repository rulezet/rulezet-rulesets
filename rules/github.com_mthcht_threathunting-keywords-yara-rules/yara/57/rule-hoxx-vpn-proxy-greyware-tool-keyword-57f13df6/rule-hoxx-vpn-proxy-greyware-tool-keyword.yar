rule rule_Hoxx_VPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hoxx VPN Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hoxx VPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Hoxx_VPN_Proxy_greyware_tool_keyword = "nbcojefnccbanplpoffopkoepjmhgdgh" nocase ascii wide

    condition:
        any of them
}