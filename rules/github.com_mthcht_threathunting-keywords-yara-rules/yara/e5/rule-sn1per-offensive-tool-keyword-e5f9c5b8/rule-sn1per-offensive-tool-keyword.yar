rule rule_Sn1per_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sn1per' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sn1per"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sn1per_offensive_tool_keyword = "1N3/Sn1per" nocase ascii wide

    condition:
        any of them
}