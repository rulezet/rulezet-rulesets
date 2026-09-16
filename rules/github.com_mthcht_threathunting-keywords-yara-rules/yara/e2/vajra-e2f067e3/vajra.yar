rule Vajra
{
    meta:
        description = "Detection patterns for the tool 'Vajra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Vajra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/bruteforce\.py/ nocase ascii wide
                        $string2 = /\/enumeration\/azureAd\.py/ nocase ascii wide
                        $string3 = /\/enumeration\/azureAzService\.py/ nocase ascii wide
                        $string4 = /\/enumeration\/subdomain\.py/ nocase ascii wide
                        $string5 = /\/enumeration\/userenum\.py/ nocase ascii wide
                        $string6 = /\/phishing\.py/ nocase ascii wide
                        $string7 = /\/spraying\.py/ nocase ascii wide
                        $string8 = "/TROUBLE-1/Vajra" nocase ascii wide
                        $string9 = /\/vajra\/phishApp\.py/ nocase ascii wide

    condition:
        any of them
}