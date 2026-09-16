rule rule_UsoDllLoader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UsoDllLoader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UsoDllLoader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UsoDllLoader_offensive_tool_keyword = "2D863D7A-A369-419C-B4B3-54BDB88B5816" nocase ascii wide
                        $string2_UsoDllLoader_offensive_tool_keyword = /tcpClient\.connectTCP\(.{0,1000}127\.0\.0\.1.{0,1000}1337/ nocase ascii wide
                        $string3_UsoDllLoader_offensive_tool_keyword = "UsoDllLoader" nocase ascii wide

    condition:
        any of them
}