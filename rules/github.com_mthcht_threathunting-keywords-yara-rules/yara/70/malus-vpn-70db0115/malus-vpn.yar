rule Malus_VPN
{
    meta:
        description = "Detection patterns for the tool 'Malus VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Malus VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bdlcnpceagnkjnjlbbbcepohejbheilk" nocase ascii wide

    condition:
        any of them
}