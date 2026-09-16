rule Hola_VPN
{
    meta:
        description = "Detection patterns for the tool 'Hola VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hola VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "kcdahmgmaagjhocpipbodaokikjkampi" nocase ascii wide

    condition:
        any of them
}