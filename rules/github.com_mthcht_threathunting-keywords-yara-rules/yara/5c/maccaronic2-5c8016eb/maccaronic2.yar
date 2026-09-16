rule MaccaroniC2
{
    meta:
        description = "Detection patterns for the tool 'MaccaroniC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaccaroniC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/asyncssh_server\.py/ nocase ascii wide
                        $string2 = "/MaccaroniC2" nocase ascii wide
                        $string3 = /\\MaccaroniC2/ nocase ascii wide
                        $string4 = /127\.0\.0\.1\:8022/ nocase ascii wide
                        $string5 = /127\.0\.0\.1\:9050/ nocase ascii wide
                        $string6 = /asyncssh_commander\.py\s/ nocase ascii wide
                        $string7 = /asyncssh_commander\.py/ nocase ascii wide
                        $string8 = "localhost:8022" nocase ascii wide
                        $string9 = /MaccaroniC2\.git/ nocase ascii wide
                        $string10 = /socks5h\:\/\/127\.0\.0\.1\:9050/ nocase ascii wide

    condition:
        any of them
}