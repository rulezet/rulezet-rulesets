rule rule_wmiexec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wmiexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wmiexec_offensive_tool_keyword = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__16.{0,1000}\s2\>\&1/ nocase ascii wide
                        $string2_wmiexec_offensive_tool_keyword = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__17.{0,1000}\s2\>\&1/ nocase ascii wide
                        $string3_wmiexec_offensive_tool_keyword = "/wmiexec/" nocase ascii wide
                        $string4_wmiexec_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\s.{0,1000}\.bat\s.{0,1000}\>\s\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\&/ nocase ascii wide
                        $string5_wmiexec_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\s\/start\s\/min\spowershell\.exe\s\-nop\s\-c/ nocase ascii wide
                        $string6_wmiexec_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\shostname1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
                        $string7_wmiexec_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\snslookup\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
                        $string8_wmiexec_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-nop\s\-w\s\-hidden\s\-c.{0,1000}IEX/ nocase ascii wide
                        $string9_wmiexec_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\spowershelll\.exe\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
                        $string10_wmiexec_offensive_tool_keyword = /cmd\.exe\s\/Q\s\/c\squser\s1\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
                        $string11_wmiexec_offensive_tool_keyword = /wmiexec\.exe\s\-hashes\s/ nocase ascii wide
                        $string12_wmiexec_offensive_tool_keyword = /wmiexec\.exe\\"\s\-hashes\s/ nocase ascii wide
                        $string13_wmiexec_offensive_tool_keyword = /WMIExec\.git/ nocase ascii wide
                        $string14_wmiexec_offensive_tool_keyword = /wmiexec_scheduledjob\.py/ nocase ascii wide
                        $string15_wmiexec_offensive_tool_keyword = /wmiexec_win32process\.py/ nocase ascii wide
                        $string16_wmiexec_offensive_tool_keyword = "WMIExec-main" nocase ascii wide

    condition:
        any of them
}