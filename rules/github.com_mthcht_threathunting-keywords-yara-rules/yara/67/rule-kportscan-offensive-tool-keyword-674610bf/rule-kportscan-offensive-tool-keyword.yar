rule rule_KPortScan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KPortScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KPortScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KPortScan_offensive_tool_keyword = /\/rdp_brute\.git/ nocase ascii wide
                        $string2_KPortScan_offensive_tool_keyword = /\\AppData\\Local\\Temp\\KPortScan/ nocase ascii wide
                        $string3_KPortScan_offensive_tool_keyword = /\\KPortScan\s3\.0\\/ nocase ascii wide
                        $string4_KPortScan_offensive_tool_keyword = /\\KPortScan\\/ nocase ascii wide
                        $string5_KPortScan_offensive_tool_keyword = "080c6108c3bd0f8a43d5647db36dc434032842339f0ba38ad1ff62f72999c4e5" nocase ascii wide
                        $string6_KPortScan_offensive_tool_keyword = /KPortScan\.exe/ nocase ascii wide
                        $string7_KPortScan_offensive_tool_keyword = /KPortScan\.rar/ nocase ascii wide
                        $string8_KPortScan_offensive_tool_keyword = /KPortScan\.zip/ nocase ascii wide
                        $string9_KPortScan_offensive_tool_keyword = /KPortScan3\.exe/ nocase ascii wide
                        $string10_KPortScan_offensive_tool_keyword = "stardust50578/rdp_brute" nocase ascii wide

    condition:
        any of them
}