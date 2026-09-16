rule rule_pivotnacci_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pivotnacci' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pivotnacci"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pivotnacci_offensive_tool_keyword = /\/pivotnacci\.git/ nocase ascii wide
                        $string2_pivotnacci_offensive_tool_keyword = "/pivotnaccilib"
                        $string3_pivotnacci_offensive_tool_keyword = "blackarrowsec/pivotnacci" nocase ascii wide
                        $string4_pivotnacci_offensive_tool_keyword = /from\s\.socks\simport\sSocksNegotiator/ nocase ascii wide
                        $string5_pivotnacci_offensive_tool_keyword = "install pivotnacci" nocase ascii wide
                        $string6_pivotnacci_offensive_tool_keyword = "install pivotnacci" nocase ascii wide
                        $string7_pivotnacci_offensive_tool_keyword = "pivotnacci  http" nocase ascii wide
                        $string8_pivotnacci_offensive_tool_keyword = "pivotnacci -" nocase ascii wide
                        $string9_pivotnacci_offensive_tool_keyword = /pivotnacci\s.{0,1000}\-\-polling\-interval/ nocase ascii wide
                        $string10_pivotnacci_offensive_tool_keyword = /pivotnacci\/0\.0\.1/ nocase ascii wide
                        $string11_pivotnacci_offensive_tool_keyword = /pivotnaccilib.{0,1000}socks/ nocase ascii wide
                        $string12_pivotnacci_offensive_tool_keyword = "pivotnacci-master" nocase ascii wide

    condition:
        any of them
}