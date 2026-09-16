rule rule_ntlmscan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntlmscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlmscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ntlmscan_offensive_tool_keyword = /\s\-\-script\=http\-ntlm\-info\s\-\-script\-args\=http\-ntlm\-info\.root\=/ nocase ascii wide
                        $string2_ntlmscan_offensive_tool_keyword = /\/ntlmscan\.git/ nocase ascii wide
                        $string3_ntlmscan_offensive_tool_keyword = "/ntlmscan/" nocase ascii wide
                        $string4_ntlmscan_offensive_tool_keyword = /ntlmscan\.py/ nocase ascii wide
                        $string5_ntlmscan_offensive_tool_keyword = /ntlmscan\-master\.zip/ nocase ascii wide
                        $string6_ntlmscan_offensive_tool_keyword = "nyxgeek/ntlmscan" nocase ascii wide

    condition:
        any of them
}