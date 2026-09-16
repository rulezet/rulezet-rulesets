rule rule_PewPewPew_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PewPewPew' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PewPewPew"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PewPewPew_offensive_tool_keyword = "8b27ef8f7cbae47922e672618e39abe7fa626c7405a67b12d7a88c1da8b06cad" nocase ascii wide
                        $string2_PewPewPew_offensive_tool_keyword = "95f9539c17bfa24ee0d7206b1fb2b195885b94e82d6bd7276bfccf2f0ceb9ac4" nocase ascii wide
                        $string3_PewPewPew_offensive_tool_keyword = "a591699874d0a2c26c1d9e47561ee2a3043fc3ea458c09a7ab8a24a25150cd0a" nocase ascii wide
                        $string4_PewPewPew_offensive_tool_keyword = "f392e058d65cc84f23773a88424d5a9e6a6987f790c52e0fb032e8538b5aec36" nocase ascii wide
                        $string5_PewPewPew_offensive_tool_keyword = /Invoke\-MassCommand\.ps1/ nocase ascii wide
                        $string6_PewPewPew_offensive_tool_keyword = "Invoke-MassMimikatz" nocase ascii wide
                        $string7_PewPewPew_offensive_tool_keyword = /Invoke\-MassSearch\.ps1/ nocase ascii wide
                        $string8_PewPewPew_offensive_tool_keyword = /Invoke\-MassTokens\.ps1/ nocase ascii wide
                        $string9_PewPewPew_offensive_tool_keyword = /Invoke\-TokenManipulation\s\-CreateProcess\s.{0,1000}cmd\.exe/ nocase ascii wide

    condition:
        any of them
}