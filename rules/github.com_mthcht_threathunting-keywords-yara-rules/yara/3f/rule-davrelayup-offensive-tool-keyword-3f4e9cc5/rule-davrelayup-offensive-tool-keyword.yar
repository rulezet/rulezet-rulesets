rule rule_DavRelayUp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DavRelayUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DavRelayUp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DavRelayUp_offensive_tool_keyword = /\/DavRelayUp\.git/ nocase ascii wide
                        $string2_DavRelayUp_offensive_tool_keyword = "/DavRelayUp/" nocase ascii wide
                        $string3_DavRelayUp_offensive_tool_keyword = /DavRelayUp\.csproj/ nocase ascii wide
                        $string4_DavRelayUp_offensive_tool_keyword = /DavRelayUp\.exe/ nocase ascii wide
                        $string5_DavRelayUp_offensive_tool_keyword = /DavRelayUp\.sln/ nocase ascii wide
                        $string6_DavRelayUp_offensive_tool_keyword = "DavRelayUp-master" nocase ascii wide
                        $string7_DavRelayUp_offensive_tool_keyword = /GoRelayServer\.dll/ nocase ascii wide
                        $string8_DavRelayUp_offensive_tool_keyword = "ShorSec/DavRelayUp" nocase ascii wide

    condition:
        any of them
}