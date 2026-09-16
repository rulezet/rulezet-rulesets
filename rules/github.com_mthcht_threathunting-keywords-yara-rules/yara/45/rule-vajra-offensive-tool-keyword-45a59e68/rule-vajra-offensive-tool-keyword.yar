rule rule_Vajra_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Vajra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Vajra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Vajra_offensive_tool_keyword = /\/bruteforce\.py/ nocase ascii wide
                        $string2_Vajra_offensive_tool_keyword = /\/enumeration\/azureAd\.py/ nocase ascii wide
                        $string3_Vajra_offensive_tool_keyword = /\/enumeration\/azureAzService\.py/ nocase ascii wide
                        $string4_Vajra_offensive_tool_keyword = /\/enumeration\/subdomain\.py/ nocase ascii wide
                        $string5_Vajra_offensive_tool_keyword = /\/enumeration\/userenum\.py/ nocase ascii wide
                        $string6_Vajra_offensive_tool_keyword = /\/phishing\.py/ nocase ascii wide
                        $string7_Vajra_offensive_tool_keyword = /\/spraying\.py/ nocase ascii wide
                        $string8_Vajra_offensive_tool_keyword = "/TROUBLE-1/Vajra" nocase ascii wide
                        $string9_Vajra_offensive_tool_keyword = /\/vajra\/phishApp\.py/ nocase ascii wide

    condition:
        any of them
}