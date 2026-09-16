rule rule_GhostTask_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GhostTask' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostTask"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GhostTask_offensive_tool_keyword = /\s\-\sdelete\:\sDelete\sa\sscheduled\stask\.\sRequires\srestarting\sthe\s/ nocase ascii wide
                        $string2_GhostTask_offensive_tool_keyword = /\sadd\s.{0,1000}\sdemon\.x64\.exe/ nocase ascii wide
                        $string3_GhostTask_offensive_tool_keyword = /\sGhostTask\.c\s/ nocase ascii wide
                        $string4_GhostTask_offensive_tool_keyword = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}daily/ nocase ascii wide
                        $string5_GhostTask_offensive_tool_keyword = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}logon/ nocase ascii wide
                        $string6_GhostTask_offensive_tool_keyword = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}second/ nocase ascii wide
                        $string7_GhostTask_offensive_tool_keyword = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}weekly/ nocase ascii wide
                        $string8_GhostTask_offensive_tool_keyword = /\.exe\slocalhost\sadd\s.{0,1000}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,1000}\\"\s.{0,1000}weekly/ nocase ascii wide
                        $string9_GhostTask_offensive_tool_keyword = /\/GhostTask\.git/ nocase ascii wide
                        $string10_GhostTask_offensive_tool_keyword = /\\GhostTask\.h/ nocase ascii wide
                        $string11_GhostTask_offensive_tool_keyword = /\\GhostTask\\/ nocase ascii wide
                        $string12_GhostTask_offensive_tool_keyword = /\\GhostTask\-1\.0\\/ nocase ascii wide
                        $string13_GhostTask_offensive_tool_keyword = /\\GhostTask\-main/ nocase ascii wide
                        $string14_GhostTask_offensive_tool_keyword = "a7ab668cab3a63df4a03cc53c46eed13fbb13bf1" nocase ascii wide
                        $string15_GhostTask_offensive_tool_keyword = /DeleteKey\(.{0,1000}SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree\\\\/ nocase ascii wide
                        $string16_GhostTask_offensive_tool_keyword = /DeleteScheduleTask\(LPCSTR\scomputerName/ nocase ascii wide
                        $string17_GhostTask_offensive_tool_keyword = /GhostTask\.exe/ nocase ascii wide
                        $string18_GhostTask_offensive_tool_keyword = /GhostTask\-1\.0\.zip/ nocase ascii wide
                        $string19_GhostTask_offensive_tool_keyword = "netero1010/GhostTask" nocase ascii wide
                        $string20_GhostTask_offensive_tool_keyword = "Successfully deleted scheduled task " nocase ascii wide

    condition:
        any of them
}