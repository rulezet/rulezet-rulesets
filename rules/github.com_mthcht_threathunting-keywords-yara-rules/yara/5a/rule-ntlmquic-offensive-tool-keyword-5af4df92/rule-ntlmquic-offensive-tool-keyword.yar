rule rule_ntlmquic_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntlmquic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlmquic"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ntlmquic_offensive_tool_keyword = "/ntlmquic" nocase ascii wide
                        $string2_ntlmquic_offensive_tool_keyword = /\/quicserver\.exe/ nocase ascii wide
                        $string3_ntlmquic_offensive_tool_keyword = /msquic_openssl\/msquic\.dll/ nocase ascii wide
                        $string4_ntlmquic_offensive_tool_keyword = /msquic_openssl\/msquic\.lib/ nocase ascii wide
                        $string5_ntlmquic_offensive_tool_keyword = /ntlmquic\./ nocase ascii wide
                        $string6_ntlmquic_offensive_tool_keyword = "ntlmquic-go" nocase ascii wide
                        $string7_ntlmquic_offensive_tool_keyword = "ntlmquic-master" nocase ascii wide
                        $string8_ntlmquic_offensive_tool_keyword = /xcopy\s\/y\s\/d\s\s.{0,1000}\\msquic_schannel\\msquic\.dll/ nocase ascii wide
                        $string9_ntlmquic_offensive_tool_keyword = /xpn.{0,1000}ntlmquic/ nocase ascii wide

    condition:
        any of them
}