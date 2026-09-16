rule Anonymous_Proxy_Vpn_Browser
{
    meta:
        description = "Detection patterns for the tool 'Anonymous Proxy Vpn Browser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Anonymous Proxy Vpn Browser"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "lklekjodgannjcccdlbicoamibgbdnmi" nocase ascii wide

    condition:
        any of them
}