rule VPN_AC
{
    meta:
        description = "Detection patterns for the tool 'VPN.AC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN.AC"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "kcndmbbelllkmioekdagahekgimemejo" nocase ascii wide

    condition:
        any of them
}