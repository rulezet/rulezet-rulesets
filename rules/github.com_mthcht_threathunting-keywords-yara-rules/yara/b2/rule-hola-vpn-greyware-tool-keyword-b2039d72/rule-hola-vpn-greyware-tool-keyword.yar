rule rule_Hola_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hola VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hola VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Hola_VPN_greyware_tool_keyword = "kcdahmgmaagjhocpipbodaokikjkampi" nocase ascii wide

    condition:
        any of them
}