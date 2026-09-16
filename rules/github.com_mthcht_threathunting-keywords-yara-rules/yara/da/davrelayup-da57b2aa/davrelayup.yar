rule DavRelayUp
{
    meta:
        description = "Detection patterns for the tool 'DavRelayUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DavRelayUp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DavRelayUp\.git/ nocase ascii wide
                        $string2 = "/DavRelayUp/" nocase ascii wide
                        $string3 = /DavRelayUp\.csproj/ nocase ascii wide
                        $string4 = /DavRelayUp\.exe/ nocase ascii wide
                        $string5 = /DavRelayUp\.sln/ nocase ascii wide
                        $string6 = "DavRelayUp-master" nocase ascii wide
                        $string7 = /GoRelayServer\.dll/ nocase ascii wide
                        $string8 = "ShorSec/DavRelayUp" nocase ascii wide

    condition:
        any of them
}