rule rule_gost_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gost"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gost_offensive_tool_keyword = /C\:\\Windows\\System\.exe.{0,1000}\s\-L\srtcp\:\/\/0\.0\.0\.0\:8087\/127\.0\.0\.1\:4444\s\-F\ssocks5\:\/\/.{0,1000}\:.{0,1000}\@.{0,1000}\:443/ nocase ascii wide
                        $string2_gost_offensive_tool_keyword = "ginuerzh/gost" nocase ascii wide
                        $string3_gost_offensive_tool_keyword = /gost\s\-L\=\:.{0,1000}\s\-F\=.{0,1000}\:/ nocase ascii wide
                        $string4_gost_offensive_tool_keyword = /gost\s\-L\=admin\:.{0,1000}\@localhost\:/ nocase ascii wide
                        $string5_gost_offensive_tool_keyword = /gost\s\-L\=forward\+ssh\:\/\/\:/ nocase ascii wide
                        $string6_gost_offensive_tool_keyword = "gost -L=rtcp://" nocase ascii wide
                        $string7_gost_offensive_tool_keyword = "gost -L=rudp://" nocase ascii wide
                        $string8_gost_offensive_tool_keyword = "gost -L=ssh://:" nocase ascii wide
                        $string9_gost_offensive_tool_keyword = "gost -L=ssu://" nocase ascii wide
                        $string10_gost_offensive_tool_keyword = "gost -L=udp://" nocase ascii wide

    condition:
        any of them
}