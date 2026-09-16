rule rule_RDPInception_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RDPInception' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPInception"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RDPInception_offensive_tool_keyword = "RDPInception" nocase ascii wide

    condition:
        any of them
}