rule rule_onesixtyone_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'onesixtyone' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onesixtyone"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_onesixtyone_offensive_tool_keyword = /\s\-i\ssnmp\-ips\.txt\s\-c\scommunity\.txt/ nocase ascii wide
                        $string2_onesixtyone_offensive_tool_keyword = /\sonesixtyone\.c/ nocase ascii wide
                        $string3_onesixtyone_offensive_tool_keyword = /\/onesixtyone\/dict\.txt/ nocase ascii wide
                        $string4_onesixtyone_offensive_tool_keyword = /onesixtyone\s\-i\s.{0,1000}\s\-c/ nocase ascii wide
                        $string5_onesixtyone_offensive_tool_keyword = /onesixtyone\.1/ nocase ascii wide
                        $string6_onesixtyone_offensive_tool_keyword = /onesixtyone\.git/ nocase ascii wide
                        $string7_onesixtyone_offensive_tool_keyword = "trailofbits/onesixtyone" nocase ascii wide

    condition:
        any of them
}