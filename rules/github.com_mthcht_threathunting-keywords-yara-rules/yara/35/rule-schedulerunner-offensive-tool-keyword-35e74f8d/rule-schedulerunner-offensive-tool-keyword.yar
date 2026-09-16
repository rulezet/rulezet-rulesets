rule rule_ScheduleRunner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ScheduleRunner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScheduleRunner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ScheduleRunner_offensive_tool_keyword = " /taskname:Cleanup " nocase ascii wide
                        $string2_ScheduleRunner_offensive_tool_keyword = /\.exe\s\/method\:create\s\/taskname\:/ nocase ascii wide
                        $string3_ScheduleRunner_offensive_tool_keyword = /\.exe\s\/method\:create\s\/taskname\:.{0,1000}\s\/trigger\:.{0,1000}\s\/modifier\:.{0,1000}\s\/program\:.{0,1000}\s\/argument\:.{0,1000}\.dll\s\/remoteserver\:/ nocase ascii wide
                        $string4_ScheduleRunner_offensive_tool_keyword = /\.exe\s\/method\:delete\s\/taskname\:.{0,1000}\s\/technique\:hide/ nocase ascii wide
                        $string5_ScheduleRunner_offensive_tool_keyword = /\.exe\s\/method\:edit\s\/taskname\:Cleanup/ nocase ascii wide
                        $string6_ScheduleRunner_offensive_tool_keyword = /\/ScheduleRunner\.git/ nocase ascii wide
                        $string7_ScheduleRunner_offensive_tool_keyword = /\[\+\]\sExecuting\stechnique\s\-\shiding\sscheduled\stask/ nocase ascii wide
                        $string8_ScheduleRunner_offensive_tool_keyword = /\[\+\]\sRemoving\sscheduled\stask\son\sdisk\sartifact/ nocase ascii wide
                        $string9_ScheduleRunner_offensive_tool_keyword = /\[\+\]\sThe\sscheduled\stask\sis\shidden\sand\sinvisible\snow/ nocase ascii wide
                        $string10_ScheduleRunner_offensive_tool_keyword = "0b8feec02a5f7915868a1ecf83aa101aa1627d9d41fa27a95352ee3f20f79508" nocase ascii wide
                        $string11_ScheduleRunner_offensive_tool_keyword = "3bd0f9a391c4fec2f65e713974067e8bdb3d99388e5f20b50c0ce867c7a5eb45" nocase ascii wide
                        $string12_ScheduleRunner_offensive_tool_keyword = "FF5F7C4C-6915-4C53-9DA3-B8BE6C5F1DB9" nocase ascii wide
                        $string13_ScheduleRunner_offensive_tool_keyword = "Hackcraft-Labs/ScheduleRunner" nocase ascii wide
                        $string14_ScheduleRunner_offensive_tool_keyword = "netero1010/ScheduleRunner" nocase ascii wide
                        $string15_ScheduleRunner_offensive_tool_keyword = /NT\sAUTHOIRTY\\SYSTEM/ nocase ascii wide
                        $string16_ScheduleRunner_offensive_tool_keyword = /ScheduleRunner\.csproj/ nocase ascii wide
                        $string17_ScheduleRunner_offensive_tool_keyword = /ScheduleRunner\.exe/ nocase ascii wide
                        $string18_ScheduleRunner_offensive_tool_keyword = /ScheduleRunner\.sln/ nocase ascii wide
                        $string19_ScheduleRunner_offensive_tool_keyword = /Using\stechnique\s\(hiding\sscheduled\stask\)\srequires\sNT\sAUTHORITY/ nocase ascii wide
                        $string20_ScheduleRunner_offensive_tool_keyword = "You do not have sufficient permission to hide the scheduled task" nocase ascii wide

    condition:
        any of them
}