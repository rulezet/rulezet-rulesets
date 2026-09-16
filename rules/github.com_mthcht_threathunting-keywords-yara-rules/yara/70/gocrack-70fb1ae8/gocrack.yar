rule gocrack
{
    meta:
        description = "Detection patterns for the tool 'gocrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gocrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/gocrack\.git/ nocase ascii wide
                        $string2 = /\/gocrack\/\.hashcat/
                        $string3 = "/gocrack/server"
                        $string4 = "/gocrack_server"
                        $string5 = "/gocrack_worker"
                        $string6 = /\/gocrack\-1\.0\.zip/
                        $string7 = "/opt/gocrack/files/engine"
                        $string8 = "/opt/gocrack/files/task"
                        $string9 = /\\gocrack\-1\.0\.zip/ nocase ascii wide
                        $string10 = /\\gocrack\-master\./ nocase ascii wide
                        $string11 = /gocrack\@password\.crackers\.local/ nocase ascii wide
                        $string12 = /gocrack_v.{0,1000}_darwin_x64_hashcat_v3_6_0\.zip/
                        $string13 = /gocrack_v.{0,1000}_linux_x64_hashcat_v3_6_0\.zip/
                        $string14 = "iAmAnIndependentStrongPassswordThatNeedsToBeSecure" nocase ascii wide
                        $string15 = "mandiant/gocrack" nocase ascii wide

    condition:
        any of them
}