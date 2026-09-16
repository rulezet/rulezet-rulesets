rule rule_RDPSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RDPSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RDPSpray_offensive_tool_keyword = "RDPSpray" nocase ascii wide

    condition:
        any of them
}