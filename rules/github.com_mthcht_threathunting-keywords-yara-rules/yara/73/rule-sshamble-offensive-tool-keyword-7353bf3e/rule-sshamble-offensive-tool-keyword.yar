rule rule_sshamble_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshamble' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshamble"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sshamble_offensive_tool_keyword = /\/sshamble\.git/ nocase ascii wide
                        $string2_sshamble_offensive_tool_keyword = "/usr/local/bin/sshamble"
                        $string3_sshamble_offensive_tool_keyword = "375f1c3e957ea3eea4956ae449e652962a57473ff55f193b8eabec033eeea187" nocase ascii wide
                        $string4_sshamble_offensive_tool_keyword = "78a924220cf74c45f237414aa61e73f066f175f0cc47649dc0668769941ed305" nocase ascii wide
                        $string5_sshamble_offensive_tool_keyword = "9e2e7dd4185ca2abe91139c009790c2a8991e8c652ef8b0d80989a4070c764f0" nocase ascii wide
                        $string6_sshamble_offensive_tool_keyword = /https\:\/\/badkeys\.info\// nocase ascii wide
                        $string7_sshamble_offensive_tool_keyword = /https\:\/\/SSHamble\.com\// nocase ascii wide
                        $string8_sshamble_offensive_tool_keyword = "runZeroInc/sshamble" nocase ascii wide
                        $string9_sshamble_offensive_tool_keyword = "sshamble scan " nocase ascii wide
                        $string10_sshamble_offensive_tool_keyword = /sshamble.{0,1000}badkeys/ nocase ascii wide
                        $string11_sshamble_offensive_tool_keyword = "sshamble/badkeys" nocase ascii wide
                        $string12_sshamble_offensive_tool_keyword = /sshamble\-main\.zip/ nocase ascii wide
                        $string13_sshamble_offensive_tool_keyword = "threatpatrols/sshamble" nocase ascii wide
                        $string14_sshamble_offensive_tool_keyword = "userenum-password-timing" nocase ascii wide

    condition:
        any of them
}