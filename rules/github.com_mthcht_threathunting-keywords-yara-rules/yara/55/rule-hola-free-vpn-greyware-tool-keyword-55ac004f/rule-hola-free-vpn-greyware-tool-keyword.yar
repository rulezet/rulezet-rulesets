rule rule_Hola_Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hola Free VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hola Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Hola_Free_VPN_greyware_tool_keyword = "gkojfkhlekighikafcpjkiklfbnlmeio" nocase ascii wide

    condition:
        any of them
}