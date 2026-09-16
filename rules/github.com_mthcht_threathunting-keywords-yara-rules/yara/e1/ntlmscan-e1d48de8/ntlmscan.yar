rule ntlmscan
{
    meta:
        description = "Detection patterns for the tool 'ntlmscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlmscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-script\=http\-ntlm\-info\s\-\-script\-args\=http\-ntlm\-info\.root\=/ nocase ascii wide
                        $string2 = /\/ntlmscan\.git/ nocase ascii wide
                        $string3 = "/ntlmscan/" nocase ascii wide
                        $string4 = /ntlmscan\.py/ nocase ascii wide
                        $string5 = /ntlmscan\-master\.zip/ nocase ascii wide
                        $string6 = "nyxgeek/ntlmscan" nocase ascii wide

    condition:
        any of them
}