rule rule_echo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'echo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_echo_greyware_tool_keyword = /\%COMSPEC\%.{0,100}echo.{0,100}\\pipe\\/ nocase ascii wide
                        $string2_echo_greyware_tool_keyword = /cmd.{0,100}echo.{0,100}\\pipe\\/ nocase ascii wide
                        $string3_echo_greyware_tool_keyword = /cmd\.exe\s\s\/S\s\/D\s\/c.{0,100}\secho\s123/ nocase ascii wide
                        $string4_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s\%username\%/ nocase ascii wide
                        $string5_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s.{0,100}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string6_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s.{0,100}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string7_echo_greyware_tool_keyword = /echo\s\'\'\'\'\s\-\/\.bash\shistory/
                        $string8_echo_greyware_tool_keyword = /echo\s\'\'\s\>\s\~\/\.bash_history/
                        $string9_echo_greyware_tool_keyword = /echo\s\\"\\"\s\>\s\/var\/log\/auth\.log\s/
                        $string10_echo_greyware_tool_keyword = "echo \"\" > /var/log/cron"
                        $string11_echo_greyware_tool_keyword = "echo \"\" > /var/log/secure"
                        $string12_echo_greyware_tool_keyword = "echo \"\" > /var/log/wtmp"
                        $string13_echo_greyware_tool_keyword = "echo \"\" > /var/spool/mail/root"
                        $string14_echo_greyware_tool_keyword = /echo\s\>\sC\:\\inetpub\\wwwroot\\.{0,100}\\.{0,100}\.aspx/ nocase ascii wide
                        $string15_echo_greyware_tool_keyword = "echo 0 > /sys/kernel/debug/kprobes/enabled"
                        $string16_echo_greyware_tool_keyword = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,100}\/tracing_on/
                        $string17_echo_greyware_tool_keyword = "echo 0 > /var/log/cron"
                        $string18_echo_greyware_tool_keyword = "echo 0 > /var/log/secure"
                        $string19_echo_greyware_tool_keyword = "echo 0 > /var/log/wtmp"
                        $string20_echo_greyware_tool_keyword = "echo 0 > /var/spool/mail/root"
                        $string21_echo_greyware_tool_keyword = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}