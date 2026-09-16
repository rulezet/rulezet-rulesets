rule nsa_rules
{
    meta:
        description = "Detection patterns for the tool 'nsa-rules' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nsa-rules"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\spwcrack\.sh/ nocase ascii wide
                        $string2 = /\/nsa\-rules\.git/ nocase ascii wide
                        $string3 = /\/pwcrack\.sh/ nocase ascii wide
                        $string4 = "NSAKEY/nsa-rules" nocase ascii wide
                        $string5 = "nsa-rules-master" nocase ascii wide

    condition:
        any of them
}