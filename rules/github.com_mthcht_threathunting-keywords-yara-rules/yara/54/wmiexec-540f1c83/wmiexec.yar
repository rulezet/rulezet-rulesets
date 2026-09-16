rule wmiexec
{
    meta:
        description = "Detection patterns for the tool 'wmiexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__16.{0,1000}\s2\>\&1/ nocase ascii wide
                        $string2 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__17.{0,1000}\s2\>\&1/ nocase ascii wide
                        $string3 = "/wmiexec/" nocase ascii wide
                        $string4 = /cmd\.exe\s\/Q\s\/c\s.{0,1000}\.bat\s.{0,1000}\>\s\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\&/ nocase ascii wide
                        $string5 = /cmd\.exe\s\/Q\s\/c\s\/start\s\/min\spowershell\.exe\s\-nop\s\-c/ nocase ascii wide
                        $string6 = /cmd\.exe\s\/Q\s\/c\shostname1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
                        $string7 = /cmd\.exe\s\/Q\s\/c\snslookup\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
                        $string8 = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-nop\s\-w\s\-hidden\s\-c.{0,1000}IEX/ nocase ascii wide
                        $string9 = /cmd\.exe\s\/Q\s\/c\spowershelll\.exe\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,1000}\s2\>/ nocase ascii wide
                        $string10 = /cmd\.exe\s\/Q\s\/c\squser\s1\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
                        $string11 = /wmiexec\.exe\s\-hashes\s/ nocase ascii wide
                        $string12 = /wmiexec\.exe\\"\s\-hashes\s/ nocase ascii wide
                        $string13 = /WMIExec\.git/ nocase ascii wide
                        $string14 = /wmiexec_scheduledjob\.py/ nocase ascii wide
                        $string15 = /wmiexec_win32process\.py/ nocase ascii wide
                        $string16 = "WMIExec-main" nocase ascii wide

    condition:
        any of them
}