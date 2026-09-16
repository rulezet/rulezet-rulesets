rule echo
{
    meta:
        description = "Detection patterns for the tool 'echo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\%COMSPEC\%.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
                        $string2 = /cmd.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
                        $string3 = /cmd\.exe\s\s\/S\s\/D\s\/c.{0,1000}\secho\s123/ nocase ascii wide
                        $string4 = /cmd\.exe\s\/c\secho\s\%username\%/ nocase ascii wide
                        $string5 = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string6 = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string7 = /echo\s\'\'\'\'\s\-\/\.bash\shistory/
                        $string8 = /echo\s\'\'\s\>\s\~\/\.bash_history/
                        $string9 = /echo\s\\"\\"\s\>\s\/var\/log\/auth\.log\s/
                        $string10 = "echo \"\" > /var/log/cron"
                        $string11 = "echo \"\" > /var/log/secure"
                        $string12 = "echo \"\" > /var/log/wtmp"
                        $string13 = "echo \"\" > /var/spool/mail/root"
                        $string14 = /echo\s\>\sC\:\\inetpub\\wwwroot\\.{0,1000}\\.{0,1000}\.aspx/ nocase ascii wide
                        $string15 = "echo 0 > /sys/kernel/debug/kprobes/enabled"
                        $string16 = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,1000}\/tracing_on/
                        $string17 = "echo 0 > /var/log/cron"
                        $string18 = "echo 0 > /var/log/secure"
                        $string19 = "echo 0 > /var/log/wtmp"
                        $string20 = "echo 0 > /var/spool/mail/root"
                        $string21 = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/

    condition:
        any of them
}