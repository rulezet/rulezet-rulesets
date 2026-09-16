rule rule_commix_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'commix' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "commix"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_commix_offensive_tool_keyword = /\/commix\.git/ nocase ascii wide
                        $string2_commix_offensive_tool_keyword = /\/commix\.py/ nocase ascii wide
                        $string3_commix_offensive_tool_keyword = "commixproject/commix" nocase ascii wide

    condition:
        any of them
}