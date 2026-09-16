rule rule_RusVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RusVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RusVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_RusVPN_greyware_tool_keyword = "hipncndjamdcmphkgngojegjblibadbe" nocase ascii wide

    condition:
        any of them
}