rule onesixtyone
{
    meta:
        description = "Detection patterns for the tool 'onesixtyone' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onesixtyone"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-i\ssnmp\-ips\.txt\s\-c\scommunity\.txt/ nocase ascii wide
                        $string2 = /\sonesixtyone\.c/ nocase ascii wide
                        $string3 = /\/onesixtyone\/dict\.txt/ nocase ascii wide
                        $string4 = /onesixtyone\s\-i\s.{0,1000}\s\-c/ nocase ascii wide
                        $string5 = /onesixtyone\.1/ nocase ascii wide
                        $string6 = /onesixtyone\.git/ nocase ascii wide
                        $string7 = "trailofbits/onesixtyone" nocase ascii wide

    condition:
        any of them
}