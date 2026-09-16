rule rule_MaccaroniC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MaccaroniC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaccaroniC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MaccaroniC2_offensive_tool_keyword = /\/asyncssh_server\.py/ nocase ascii wide
                        $string2_MaccaroniC2_offensive_tool_keyword = "/MaccaroniC2" nocase ascii wide
                        $string3_MaccaroniC2_offensive_tool_keyword = /\\MaccaroniC2/ nocase ascii wide
                        $string4_MaccaroniC2_offensive_tool_keyword = /127\.0\.0\.1\:8022/ nocase ascii wide
                        $string5_MaccaroniC2_offensive_tool_keyword = /127\.0\.0\.1\:9050/ nocase ascii wide
                        $string6_MaccaroniC2_offensive_tool_keyword = /asyncssh_commander\.py\s/ nocase ascii wide
                        $string7_MaccaroniC2_offensive_tool_keyword = /asyncssh_commander\.py/ nocase ascii wide
                        $string8_MaccaroniC2_offensive_tool_keyword = "localhost:8022" nocase ascii wide
                        $string9_MaccaroniC2_offensive_tool_keyword = /MaccaroniC2\.git/ nocase ascii wide
                        $string10_MaccaroniC2_offensive_tool_keyword = /socks5h\:\/\/127\.0\.0\.1\:9050/ nocase ascii wide

    condition:
        any of them
}