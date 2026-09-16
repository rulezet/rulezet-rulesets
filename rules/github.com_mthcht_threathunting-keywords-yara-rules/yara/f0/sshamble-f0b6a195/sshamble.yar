rule sshamble
{
    meta:
        description = "Detection patterns for the tool 'sshamble' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshamble"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/sshamble\.git/ nocase ascii wide
                        $string2 = "/usr/local/bin/sshamble"
                        $string3 = "375f1c3e957ea3eea4956ae449e652962a57473ff55f193b8eabec033eeea187" nocase ascii wide
                        $string4 = "78a924220cf74c45f237414aa61e73f066f175f0cc47649dc0668769941ed305" nocase ascii wide
                        $string5 = "9e2e7dd4185ca2abe91139c009790c2a8991e8c652ef8b0d80989a4070c764f0" nocase ascii wide
                        $string6 = /https\:\/\/badkeys\.info\// nocase ascii wide
                        $string7 = /https\:\/\/SSHamble\.com\// nocase ascii wide
                        $string8 = "runZeroInc/sshamble" nocase ascii wide
                        $string9 = "sshamble scan " nocase ascii wide
                        $string10 = /sshamble.{0,1000}badkeys/ nocase ascii wide
                        $string11 = "sshamble/badkeys" nocase ascii wide
                        $string12 = /sshamble\-main\.zip/ nocase ascii wide
                        $string13 = "threatpatrols/sshamble" nocase ascii wide
                        $string14 = "userenum-password-timing" nocase ascii wide

    condition:
        any of them
}