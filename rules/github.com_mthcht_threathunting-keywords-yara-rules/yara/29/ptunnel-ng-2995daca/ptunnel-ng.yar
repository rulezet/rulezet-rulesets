rule ptunnel_ng
{
    meta:
        description = "Detection patterns for the tool 'ptunnel-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ptunnel-ng"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " ptunnel-ng" nocase ascii wide
                        $string2 = "/ptunnel-ng" nocase ascii wide
                        $string3 = "/var/lib/ptunnel"
                        $string4 = /nc\s127\.0\.0\.1\s4000/ nocase ascii wide
                        $string5 = /new\ssession\sto\s127\.0\.0\.1\:3000/ nocase ascii wide
                        $string6 = /ptunnel\-client\.log/ nocase ascii wide
                        $string7 = "ptunnel-data-recv" nocase ascii wide
                        $string8 = "ptunnel-data-send" nocase ascii wide
                        $string9 = "ptunnel-master" nocase ascii wide
                        $string10 = "ptunnel-ng " nocase ascii wide
                        $string11 = /ptunnel\-ng\.conf/ nocase ascii wide
                        $string12 = /ptunnel\-ng\.git/ nocase ascii wide
                        $string13 = /ptunnel\-ng\.service/ nocase ascii wide
                        $string14 = /ptunnel\-ng\.te/ nocase ascii wide
                        $string15 = /ptunnel\-ng\-x64\.exe/ nocase ascii wide
                        $string16 = /ptunnel\-ng\-x64\-dbg\.exe/ nocase ascii wide
                        $string17 = /ptunnel\-ng\-x86\.exe/ nocase ascii wide
                        $string18 = /ptunnel\-ng\-x86\-dbg\.exe/ nocase ascii wide
                        $string19 = /ptunnel\-server\.log/ nocase ascii wide

    condition:
        any of them
}