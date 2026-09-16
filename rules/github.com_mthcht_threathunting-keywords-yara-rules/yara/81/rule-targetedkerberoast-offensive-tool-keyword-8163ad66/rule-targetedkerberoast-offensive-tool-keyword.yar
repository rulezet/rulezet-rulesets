rule rule_targetedKerberoast_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'targetedKerberoast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "targetedKerberoast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_targetedKerberoast_offensive_tool_keyword = "/targetedKerberoast" nocase ascii wide
                        $string2_targetedKerberoast_offensive_tool_keyword = /kerberoastables\.txt/ nocase ascii wide
                        $string3_targetedKerberoast_offensive_tool_keyword = /targetedKerberoast\.git/ nocase ascii wide
                        $string4_targetedKerberoast_offensive_tool_keyword = /targetedKerberoast\.py/ nocase ascii wide
                        $string5_targetedKerberoast_offensive_tool_keyword = "targetedKerberoast-main" nocase ascii wide

    condition:
        any of them
}