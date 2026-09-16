rule DelegationBOF
{
    meta:
        description = "Detection patterns for the tool 'DelegationBOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DelegationBOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/DelegationBOF/" nocase ascii wide
                        $string2 = /\\DelegationBOF\./ nocase ascii wide
                        $string3 = /DelegationBOF\./ nocase ascii wide
                        $string4 = /get\-delegation\s.{0,1000}All/ nocase ascii wide
                        $string5 = /get\-delegation\s.{0,1000}Unconstrained/ nocase ascii wide
                        $string6 = "get-spns All" nocase ascii wide
                        $string7 = "get-spns ASREP" nocase ascii wide
                        $string8 = "get-spns spns" nocase ascii wide
                        $string9 = "IcebreakerSecurity/DelegationBOF" nocase ascii wide

    condition:
        any of them
}