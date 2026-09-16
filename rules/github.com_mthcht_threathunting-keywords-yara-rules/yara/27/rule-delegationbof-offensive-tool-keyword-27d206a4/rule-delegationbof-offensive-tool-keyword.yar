rule rule_DelegationBOF_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DelegationBOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DelegationBOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DelegationBOF_offensive_tool_keyword = "/DelegationBOF/" nocase ascii wide
                        $string2_DelegationBOF_offensive_tool_keyword = /\\DelegationBOF\./ nocase ascii wide
                        $string3_DelegationBOF_offensive_tool_keyword = /DelegationBOF\./ nocase ascii wide
                        $string4_DelegationBOF_offensive_tool_keyword = /get\-delegation\s.{0,1000}All/ nocase ascii wide
                        $string5_DelegationBOF_offensive_tool_keyword = /get\-delegation\s.{0,1000}Unconstrained/ nocase ascii wide
                        $string6_DelegationBOF_offensive_tool_keyword = "get-spns All" nocase ascii wide
                        $string7_DelegationBOF_offensive_tool_keyword = "get-spns ASREP" nocase ascii wide
                        $string8_DelegationBOF_offensive_tool_keyword = "get-spns spns" nocase ascii wide
                        $string9_DelegationBOF_offensive_tool_keyword = "IcebreakerSecurity/DelegationBOF" nocase ascii wide

    condition:
        any of them
}