rule rule_echo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'echo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_echo_greyware_tool_keyword = /\%COMSPEC\%.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
                        $string2_echo_greyware_tool_keyword = /cmd.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
                        $string3_echo_greyware_tool_keyword = /cmd\.exe\s\s\/S\s\/D\s\/c.{0,1000}\secho\s123/ nocase ascii wide
                        $string4_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s\%username\%/ nocase ascii wide
                        $string5_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string6_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string7_echo_greyware_tool_keyword = /echo\s\'\'\'\'\s\-\/\.bash\shistory/
                        $string8_echo_greyware_tool_keyword = /echo\s\'\'\s\>\s\~\/\.bash_history/
                        $string9_echo_greyware_tool_keyword = /echo\s\\"\\"\s\>\s\/var\/log\/auth\.log\s/
                        $string10_echo_greyware_tool_keyword = "echo \"\" > /var/log/cron"
                        $string11_echo_greyware_tool_keyword = "echo \"\" > /var/log/secure"
                        $string12_echo_greyware_tool_keyword = "echo \"\" > /var/log/wtmp"
                        $string13_echo_greyware_tool_keyword = "echo \"\" > /var/spool/mail/root"
                        $string14_echo_greyware_tool_keyword = /echo\s\>\sC\:\\inetpub\\wwwroot\\.{0,1000}\\.{0,1000}\.aspx/ nocase ascii wide
                        $string15_echo_greyware_tool_keyword = "echo 0 > /sys/kernel/debug/kprobes/enabled"
                        $string16_echo_greyware_tool_keyword = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,1000}\/tracing_on/
                        $string17_echo_greyware_tool_keyword = "echo 0 > /var/log/cron"
                        $string18_echo_greyware_tool_keyword = "echo 0 > /var/log/secure"
                        $string19_echo_greyware_tool_keyword = "echo 0 > /var/log/wtmp"
                        $string20_echo_greyware_tool_keyword = "echo 0 > /var/spool/mail/root"
                        $string21_echo_greyware_tool_keyword = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/

    condition:
        any of them
}