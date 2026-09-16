rule ntlmquic
{
    meta:
        description = "Detection patterns for the tool 'ntlmquic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlmquic"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ntlmquic" nocase ascii wide
                        $string2 = /\/quicserver\.exe/ nocase ascii wide
                        $string3 = /msquic_openssl\/msquic\.dll/ nocase ascii wide
                        $string4 = /msquic_openssl\/msquic\.lib/ nocase ascii wide
                        $string5 = /ntlmquic\./ nocase ascii wide
                        $string6 = "ntlmquic-go" nocase ascii wide
                        $string7 = "ntlmquic-master" nocase ascii wide
                        $string8 = /xcopy\s\/y\s\/d\s\s.{0,1000}\\msquic_schannel\\msquic\.dll/ nocase ascii wide
                        $string9 = /xpn.{0,1000}ntlmquic/ nocase ascii wide

    condition:
        any of them
}