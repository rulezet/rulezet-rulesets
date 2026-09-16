rule RusVPN
{
    meta:
        description = "Detection patterns for the tool 'RusVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RusVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "hipncndjamdcmphkgngojegjblibadbe" nocase ascii wide

    condition:
        any of them
}