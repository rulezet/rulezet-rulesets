rule GhostTask
{
    meta:
        description = "Detection patterns for the tool 'GhostTask' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostTask"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\sdelete\:\sDelete\sa\sscheduled\stask\.\sRequires\srestarting\sthe\s/ nocase ascii wide
                        $string2 = /\sadd\s.{0,1000}\sdemon\.x64\.exe/ nocase ascii wide
                        $string3 = /\sGhostTask\.c\s/ nocase ascii wide
                        $string4 = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}daily/ nocase ascii wide
                        $string5 = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}logon/ nocase ascii wide
                        $string6 = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}second/ nocase ascii wide
                        $string7 = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}weekly/ nocase ascii wide
                        $string8 = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}weekly/ nocase ascii wide
                        $string9 = /\/GhostTask\.git/ nocase ascii wide
                        $string10 = /\\GhostTask\.h/ nocase ascii wide
                        $string11 = /\\GhostTask\\/ nocase ascii wide
                        $string12 = /\\GhostTask\-1\.0\\/ nocase ascii wide
                        $string13 = /\\GhostTask\-main/ nocase ascii wide
                        $string14 = "a7ab668cab3a63df4a03cc53c46eed13fbb13bf1" nocase ascii wide
                        $string15 = /DeleteKey\(.{0,1000}SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree\\\\/ nocase ascii wide
                        $string16 = /DeleteScheduleTask\(LPCSTR\scomputerName/ nocase ascii wide
                        $string17 = /GhostTask\.exe/ nocase ascii wide
                        $string18 = /GhostTask\-1\.0\.zip/ nocase ascii wide
                        $string19 = "netero1010/GhostTask" nocase ascii wide
                        $string20 = "Successfully deleted scheduled task " nocase ascii wide

    condition:
        any of them
}