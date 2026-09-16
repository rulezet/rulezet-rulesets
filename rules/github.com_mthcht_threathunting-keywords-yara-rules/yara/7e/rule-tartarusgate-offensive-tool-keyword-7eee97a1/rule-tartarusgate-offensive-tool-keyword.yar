rule rule_TartarusGate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TartarusGate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TartarusGate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TartarusGate_offensive_tool_keyword = /\/TartarusGate\.git/ nocase ascii wide
                        $string2_TartarusGate_offensive_tool_keyword = "DC6187CB-D5DF-4973-84A2-F92AAE90CDA9" nocase ascii wide
                        $string3_TartarusGate_offensive_tool_keyword = "TartarusGate-master" nocase ascii wide
                        $string4_TartarusGate_offensive_tool_keyword = "trickster0/TartarusGate" nocase ascii wide

    condition:
        any of them
}