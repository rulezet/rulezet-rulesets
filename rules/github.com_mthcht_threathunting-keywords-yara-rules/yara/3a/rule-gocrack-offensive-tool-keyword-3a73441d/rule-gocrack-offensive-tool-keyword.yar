rule rule_gocrack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gocrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gocrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gocrack_offensive_tool_keyword = /\/gocrack\.git/ nocase ascii wide
                        $string2_gocrack_offensive_tool_keyword = /\/gocrack\/\.hashcat/
                        $string3_gocrack_offensive_tool_keyword = "/gocrack/server"
                        $string4_gocrack_offensive_tool_keyword = "/gocrack_server"
                        $string5_gocrack_offensive_tool_keyword = "/gocrack_worker"
                        $string6_gocrack_offensive_tool_keyword = /\/gocrack\-1\.0\.zip/
                        $string7_gocrack_offensive_tool_keyword = "/opt/gocrack/files/engine"
                        $string8_gocrack_offensive_tool_keyword = "/opt/gocrack/files/task"
                        $string9_gocrack_offensive_tool_keyword = /\\gocrack\-1\.0\.zip/ nocase ascii wide
                        $string10_gocrack_offensive_tool_keyword = /\\gocrack\-master\./ nocase ascii wide
                        $string11_gocrack_offensive_tool_keyword = /gocrack\@password\.crackers\.local/ nocase ascii wide
                        $string12_gocrack_offensive_tool_keyword = /gocrack_v.{0,1000}_darwin_x64_hashcat_v3_6_0\.zip/
                        $string13_gocrack_offensive_tool_keyword = /gocrack_v.{0,1000}_linux_x64_hashcat_v3_6_0\.zip/
                        $string14_gocrack_offensive_tool_keyword = "iAmAnIndependentStrongPassswordThatNeedsToBeSecure" nocase ascii wide
                        $string15_gocrack_offensive_tool_keyword = "mandiant/gocrack" nocase ascii wide

    condition:
        any of them
}