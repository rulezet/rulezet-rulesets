rule echo
{
    meta:
        description = "Detection patterns for the tool 'echo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\%COMSPEC\%.{0,100}echo.{0,100}\\pipe\\/ nocase ascii wide
                        $string2 = /cmd.{0,100}echo.{0,100}\\pipe\\/ nocase ascii wide
                        $string3 = /cmd\.exe\s\s\/S\s\/D\s\/c.{0,100}\secho\s123/ nocase ascii wide
                        $string4 = /cmd\.exe\s\/c\secho\s\%username\%/ nocase ascii wide
                        $string5 = /cmd\.exe\s\/c\secho\s.{0,100}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string6 = /cmd\.exe\s\/c\secho\s.{0,100}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
                        $string7 = /echo\s\'\'\'\'\s\-\/\.bash\shistory/
                        $string8 = /echo\s\'\'\s\>\s\~\/\.bash_history/
                        $string9 = /echo\s\\"\\"\s\>\s\/var\/log\/auth\.log\s/
                        $string10 = "echo \"\" > /var/log/cron"
                        $string11 = "echo \"\" > /var/log/secure"
                        $string12 = "echo \"\" > /var/log/wtmp"
                        $string13 = "echo \"\" > /var/spool/mail/root"
                        $string14 = /echo\s\>\sC\:\\inetpub\\wwwroot\\.{0,100}\\.{0,100}\.aspx/ nocase ascii wide
                        $string15 = "echo 0 > /sys/kernel/debug/kprobes/enabled"
                        $string16 = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,100}\/tracing_on/
                        $string17 = "echo 0 > /var/log/cron"
                        $string18 = "echo 0 > /var/log/secure"
                        $string19 = "echo 0 > /var/log/wtmp"
                        $string20 = "echo 0 > /var/spool/mail/root"
                        $string21 = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/
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