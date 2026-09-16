rule rule_Browsec_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browsec VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browsec VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Browsec_VPN_greyware_tool_keyword = "omghfjlpggmjjaagoclmmobgdodcjboh" nocase ascii wide

    condition:
        any of them
}