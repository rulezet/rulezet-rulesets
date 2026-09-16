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
                        $string2 = /\sadd\s.{0,100}\sdemon\.x64\.exe/ nocase ascii wide
                        $string3 = /\sGhostTask\.c\s/ nocase ascii wide
                        $string4 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}daily/ nocase ascii wide
                        $string5 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}logon/ nocase ascii wide
                        $string6 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}second/ nocase ascii wide
                        $string7 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}weekly/ nocase ascii wide
                        $string8 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}weekly/ nocase ascii wide
                        $string9 = /\/GhostTask\.git/ nocase ascii wide
                        $string10 = /\\GhostTask\.h/ nocase ascii wide
                        $string11 = /\\GhostTask\\/ nocase ascii wide
                        $string12 = /\\GhostTask\-1\.0\\/ nocase ascii wide
                        $string13 = /\\GhostTask\-main/ nocase ascii wide
                        $string14 = "a7ab668cab3a63df4a03cc53c46eed13fbb13bf1" nocase ascii wide
                        $string15 = /DeleteKey\(.{0,100}SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree\\\\/ nocase ascii wide
                        $string16 = /DeleteScheduleTask\(LPCSTR\scomputerName/ nocase ascii wide
                        $string17 = /GhostTask\.exe/ nocase ascii wide
                        $string18 = /GhostTask\-1\.0\.zip/ nocase ascii wide
                        $string19 = "netero1010/GhostTask" nocase ascii wide
                        $string20 = "Successfully deleted scheduled task " nocase ascii wide
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