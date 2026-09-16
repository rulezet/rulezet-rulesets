rule rule_PSRansom_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSRansom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRansom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSRansom_offensive_tool_keyword = " PopUpRansom" nocase ascii wide
                        $string2_PSRansom_offensive_tool_keyword = "/PSRansom -" nocase ascii wide
                        $string3_PSRansom_offensive_tool_keyword = /\\PSRansom\s\-/ nocase ascii wide
                        $string4_PSRansom_offensive_tool_keyword = "644e2fa03a4d45b8d0417819a7548339069df8d405131039006968b312c8c6f4" nocase ascii wide
                        $string5_PSRansom_offensive_tool_keyword = "C2Server by @JoelGMSec" nocase ascii wide
                        $string6_PSRansom_offensive_tool_keyword = /C2Server\.ps1/ nocase ascii wide
                        $string7_PSRansom_offensive_tool_keyword = "cf78b329b4dcb1c211415309e2ddbf80833ad1669fd142a67c916aa6a8cecb88" nocase ascii wide
                        $string8_PSRansom_offensive_tool_keyword = "JoelGMSec/PSRansom" nocase ascii wide
                        $string9_PSRansom_offensive_tool_keyword = "PSRansom by @JoelGMSec" nocase ascii wide
                        $string10_PSRansom_offensive_tool_keyword = /PSRansom\.ps1/ nocase ascii wide
                        $string11_PSRansom_offensive_tool_keyword = "pwd/C2Files/" nocase ascii wide
                        $string12_PSRansom_offensive_tool_keyword = /pwd\\C2Files\\/ nocase ascii wide

    condition:
        any of them
}