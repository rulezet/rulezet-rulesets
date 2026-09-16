rule Cloud_VPN
{
    meta:
        description = "Detection patterns for the tool 'Cloud VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cloud VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "pcienlhnoficegnepejpfiklggkioccm" nocase ascii wide

    condition:
        any of them
}