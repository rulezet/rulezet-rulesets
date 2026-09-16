rule rule_Anonymous_Proxy_Vpn_Browser_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Anonymous Proxy Vpn Browser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Anonymous Proxy Vpn Browser"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Anonymous_Proxy_Vpn_Browser_greyware_tool_keyword = "lklekjodgannjcccdlbicoamibgbdnmi" nocase ascii wide

    condition:
        any of them
}