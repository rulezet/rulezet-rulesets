rule wmiexec
{
    meta:
        description = "Detection patterns for the tool 'wmiexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__16.{0,100}\s2\>\&1/ nocase ascii wide
                        $string2 = /\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__17.{0,100}\s2\>\&1/ nocase ascii wide
                        $string3 = "/wmiexec/" nocase ascii wide
                        $string4 = /cmd\.exe\s\/Q\s\/c\s.{0,100}\.bat\s.{0,100}\>\s\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\&/ nocase ascii wide
                        $string5 = /cmd\.exe\s\/Q\s\/c\s\/start\s\/min\spowershell\.exe\s\-nop\s\-c/ nocase ascii wide
                        $string6 = /cmd\.exe\s\/Q\s\/c\shostname1\>\s.{0,100}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\>/ nocase ascii wide
                        $string7 = /cmd\.exe\s\/Q\s\/c\snslookup\s1\>\s.{0,100}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\>/ nocase ascii wide
                        $string8 = /cmd\.exe\s\/Q\s\/c\spowershell\.exe\s\-nop\s\-w\s\-hidden\s\-c.{0,100}IEX/ nocase ascii wide
                        $string9 = /cmd\.exe\s\/Q\s\/c\spowershelll\.exe\s1\>\s.{0,100}\\\\127\.0\.0\.1\\ADMIN\$\\.{0,100}\s2\>/ nocase ascii wide
                        $string10 = /cmd\.exe\s\/Q\s\/c\squser\s1\s\>\s\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
                        $string11 = /wmiexec\.exe\s\-hashes\s/ nocase ascii wide
                        $string12 = /wmiexec\.exe\\"\s\-hashes\s/ nocase ascii wide
                        $string13 = /WMIExec\.git/ nocase ascii wide
                        $string14 = /wmiexec_scheduledjob\.py/ nocase ascii wide
                        $string15 = /wmiexec_win32process\.py/ nocase ascii wide
                        $string16 = "WMIExec-main" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}