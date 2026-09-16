rule rule_speedtest_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'speedtest' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "speedtest"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_speedtest_greyware_tool_keyword = /\/raw\/main\/speedtest\.exe/ nocase ascii wide
                        $string2_speedtest_greyware_tool_keyword = /\/raw\/master\/speedtest\.exe/ nocase ascii wide
                        $string3_speedtest_greyware_tool_keyword = /\\speedtest\.exe\s\-\-accept\-license/ nocase ascii wide
                        $string4_speedtest_greyware_tool_keyword = /\\speedtest\.exe\\"\s\-\-accept\-license/ nocase ascii wide
                        $string5_speedtest_greyware_tool_keyword = "dffc17b4b0f9c841d94802e2c9578758dbb52ca1ab967a506992c26aabecc43a" nocase ascii wide
                        $string6_speedtest_greyware_tool_keyword = /ProgramData\\speedtest\.exe/ nocase ascii wide
                        $string7_speedtest_greyware_tool_keyword = /ProgramData\\SpeedtestCLI/ nocase ascii wide

    condition:
        any of them
}