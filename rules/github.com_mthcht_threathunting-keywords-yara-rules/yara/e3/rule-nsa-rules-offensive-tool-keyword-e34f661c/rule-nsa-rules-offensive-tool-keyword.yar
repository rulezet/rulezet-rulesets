rule rule_nsa_rules_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nsa-rules' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nsa-rules"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nsa_rules_offensive_tool_keyword = /\spwcrack\.sh/ nocase ascii wide
                        $string2_nsa_rules_offensive_tool_keyword = /\/nsa\-rules\.git/ nocase ascii wide
                        $string3_nsa_rules_offensive_tool_keyword = /\/pwcrack\.sh/ nocase ascii wide
                        $string4_nsa_rules_offensive_tool_keyword = "NSAKEY/nsa-rules" nocase ascii wide
                        $string5_nsa_rules_offensive_tool_keyword = "nsa-rules-master" nocase ascii wide

    condition:
        any of them
}