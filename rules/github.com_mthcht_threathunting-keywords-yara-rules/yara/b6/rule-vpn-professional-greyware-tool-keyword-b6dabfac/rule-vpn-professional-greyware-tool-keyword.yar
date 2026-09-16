rule rule_VPN_Professional_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN Professional' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Professional"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_VPN_Professional_greyware_tool_keyword = "foiopecknacmiihiocgdjgbjokkpkohc" nocase ascii wide

    condition:
        any of them
}