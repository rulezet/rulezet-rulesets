rule OffensiveCpp
{
    meta:
        description = "Detection patterns for the tool 'OffensiveCpp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveCpp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sadmin_persistence_winlogon\.c/ nocase ascii wide
                        $string2 = /\sSMB_Staging\.c/ nocase ascii wide
                        $string3 = /\suser_persistence_run\.c/ nocase ascii wide
                        $string4 = /\/admin_persistence_winlogon\.c/ nocase ascii wide
                        $string5 = /\/OffensiveCpp\.git/ nocase ascii wide
                        $string6 = /\/thread\-injector\.exe/ nocase ascii wide
                        $string7 = /\/user_persistence_run\.c/ nocase ascii wide
                        $string8 = /\\\\\\\\.{0,100}\\\\share\\\\test\.bin/ nocase ascii wide
                        $string9 = /\\admin_persistence_winlogon/ nocase ascii wide
                        $string10 = /\\Evasion\\Sandbox\sEvasion\\.{0,100}\.c/ nocase ascii wide
                        $string11 = /\\Evasion\\Sandbox\sEvasion\\.{0,100}\.exe/ nocase ascii wide
                        $string12 = /\\OffensiveCpp\\/ nocase ascii wide
                        $string13 = /\\OffensiveCpp\-main/ nocase ascii wide
                        $string14 = /\\Shellcode\sExecution\\CertEnumSystemStore\\/ nocase ascii wide
                        $string15 = /\\Shellcode\sExecution\\Enum/ nocase ascii wide
                        $string16 = /\\SMB_Staging\.c/ nocase ascii wide
                        $string17 = /\\thread\-injector\.exe/ nocase ascii wide
                        $string18 = /\\user_persistence_run\.c/ nocase ascii wide
                        $string19 = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
                        $string20 = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
                        $string21 = "a8944d1ff8c72e68ca1bb55dad84aae6cb7d4cbcc92d442dc8497c8949a96adc" nocase ascii wide
                        $string22 = "d3366dc09c1ec4e93c9a40f4de0f96088786b6fb44b3fafb3d648a4b6342b596" nocase ascii wide
                        $string23 = "fbb4a1a49a0683247e83da8d2ccd4bdab51516a0a5cacbf6ff759213792e58e2" nocase ascii wide
                        $string24 = /If\sno\sprocess\sprovided\,\sit\swill\sattempt\sto\sinject\sinto\sexplorer\.exe/ nocase ascii wide
                        $string25 = "JohnWoodman/stealthInjector" nocase ascii wide
                        $string26 = "lsecqt/OffensiveCpp" nocase ascii wide
                        $string27 = "No sandbox-indicative DLLs were discovered loaded in any accessible running process" nocase ascii wide
                        $string28 = /thread\-injector\.exe\s/ nocase ascii wide
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