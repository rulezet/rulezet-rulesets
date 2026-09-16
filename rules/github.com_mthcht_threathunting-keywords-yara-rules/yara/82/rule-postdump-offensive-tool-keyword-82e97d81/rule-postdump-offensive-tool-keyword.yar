rule rule_POSTDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'POSTDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "POSTDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_POSTDump_offensive_tool_keyword = /\sPostDump\.exe/ nocase ascii wide
                        $string2_POSTDump_offensive_tool_keyword = /\.exe\s\-\-signature\s\-\-driver/ nocase ascii wide
                        $string3_POSTDump_offensive_tool_keyword = /\/PostDump\.exe/ nocase ascii wide
                        $string4_POSTDump_offensive_tool_keyword = /\/POSTDump\.git/ nocase ascii wide
                        $string5_POSTDump_offensive_tool_keyword = /\\lsass\.dmp/ nocase ascii wide
                        $string6_POSTDump_offensive_tool_keyword = /\\POSTDump\.csproj/ nocase ascii wide
                        $string7_POSTDump_offensive_tool_keyword = /\\PostDump\.exe/ nocase ascii wide
                        $string8_POSTDump_offensive_tool_keyword = /\\POSTDump\.sln/ nocase ascii wide
                        $string9_POSTDump_offensive_tool_keyword = /\\POSTDump\\POSTDump\\/ nocase ascii wide
                        $string10_POSTDump_offensive_tool_keyword = /\\POSTMiniDump\\/ nocase ascii wide
                        $string11_POSTDump_offensive_tool_keyword = /ASR_bypass_to_dump_LSASS\.cs/ nocase ascii wide
                        $string12_POSTDump_offensive_tool_keyword = /copy\s.{0,100}PROCEXP\.sys.{0,100}C\:\\Windows\\System32\\WindowsPowershell\\/ nocase ascii wide
                        $string13_POSTDump_offensive_tool_keyword = /Done\!\sCheck\sfor\sexisting\slsass\.dmp\sfile\sinto\scurrent\sfolder/ nocase ascii wide
                        $string14_POSTDump_offensive_tool_keyword = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase ascii wide
                        $string15_POSTDump_offensive_tool_keyword = "Invoke-PostDump" nocase ascii wide
                        $string16_POSTDump_offensive_tool_keyword = "namespace POSTDump" nocase ascii wide
                        $string17_POSTDump_offensive_tool_keyword = "namespace POSTMiniDump" nocase ascii wide
                        $string18_POSTDump_offensive_tool_keyword = /POSTDump.{0,100}PROCEXP\.sys/ nocase ascii wide
                        $string19_POSTDump_offensive_tool_keyword = /PostDump\.exe\s/ nocase ascii wide
                        $string20_POSTDump_offensive_tool_keyword = /POSTDump\.git/ nocase ascii wide
                        $string21_POSTDump_offensive_tool_keyword = /PostDump\.ps1/ nocase ascii wide
                        $string22_POSTDump_offensive_tool_keyword = /POSTDump\\Postdump\.cs/ nocase ascii wide
                        $string23_POSTDump_offensive_tool_keyword = /POSTDump\\PROCEXP\.sys/ nocase ascii wide
                        $string24_POSTDump_offensive_tool_keyword = "POSTDump-main" nocase ascii wide
                        $string25_POSTDump_offensive_tool_keyword = /POSTMiniDump\.Data/ nocase ascii wide
                        $string26_POSTDump_offensive_tool_keyword = /POSTMiniDump\.MiniDump/ nocase ascii wide
                        $string27_POSTDump_offensive_tool_keyword = /POSTMiniDump\.Utils/ nocase ascii wide
                        $string28_POSTDump_offensive_tool_keyword = /python3\sdump\-restore\.py/ nocase ascii wide
                        $string29_POSTDump_offensive_tool_keyword = "YOLOP0wn/POSTDump" nocase ascii wide
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