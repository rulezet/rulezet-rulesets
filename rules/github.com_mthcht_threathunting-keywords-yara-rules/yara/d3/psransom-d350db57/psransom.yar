rule PSRansom
{
    meta:
        description = "Detection patterns for the tool 'PSRansom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRansom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " PopUpRansom" nocase ascii wide
                        $string2 = "/PSRansom -" nocase ascii wide
                        $string3 = /\\PSRansom\s\-/ nocase ascii wide
                        $string4 = "644e2fa03a4d45b8d0417819a7548339069df8d405131039006968b312c8c6f4" nocase ascii wide
                        $string5 = "C2Server by @JoelGMSec" nocase ascii wide
                        $string6 = /C2Server\.ps1/ nocase ascii wide
                        $string7 = "cf78b329b4dcb1c211415309e2ddbf80833ad1669fd142a67c916aa6a8cecb88" nocase ascii wide
                        $string8 = "JoelGMSec/PSRansom" nocase ascii wide
                        $string9 = "PSRansom by @JoelGMSec" nocase ascii wide
                        $string10 = /PSRansom\.ps1/ nocase ascii wide
                        $string11 = "pwd/C2Files/" nocase ascii wide
                        $string12 = /pwd\\C2Files\\/ nocase ascii wide

    condition:
        any of them
}