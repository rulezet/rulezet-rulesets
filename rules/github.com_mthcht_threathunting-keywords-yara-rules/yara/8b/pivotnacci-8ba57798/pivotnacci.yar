rule pivotnacci
{
    meta:
        description = "Detection patterns for the tool 'pivotnacci' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pivotnacci"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/pivotnacci\.git/ nocase ascii wide
                        $string2 = "/pivotnaccilib"
                        $string3 = "blackarrowsec/pivotnacci" nocase ascii wide
                        $string4 = /from\s\.socks\simport\sSocksNegotiator/ nocase ascii wide
                        $string5 = "install pivotnacci" nocase ascii wide
                        $string6 = "install pivotnacci" nocase ascii wide
                        $string7 = "pivotnacci  http" nocase ascii wide
                        $string8 = "pivotnacci -" nocase ascii wide
                        $string9 = /pivotnacci\s.{0,1000}\-\-polling\-interval/ nocase ascii wide
                        $string10 = /pivotnacci\/0\.0\.1/ nocase ascii wide
                        $string11 = /pivotnaccilib.{0,1000}socks/ nocase ascii wide
                        $string12 = "pivotnacci-master" nocase ascii wide

    condition:
        any of them
}