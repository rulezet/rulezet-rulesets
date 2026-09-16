rule rule_PoolParty_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PoolParty' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoolParty"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PoolParty_offensive_tool_keyword = /\sPoolParty\.cpp/ nocase ascii wide
                        $string2_PoolParty_offensive_tool_keyword = /\sPoolParty\.exe/ nocase ascii wide
                        $string3_PoolParty_offensive_tool_keyword = /\/HandleHijacker\.cpp/ nocase ascii wide
                        $string4_PoolParty_offensive_tool_keyword = /\/HandleHijacker\.hpp/ nocase ascii wide
                        $string5_PoolParty_offensive_tool_keyword = /\/PoolParty\.cpp/ nocase ascii wide
                        $string6_PoolParty_offensive_tool_keyword = /\/PoolParty\.exe/ nocase ascii wide
                        $string7_PoolParty_offensive_tool_keyword = /\/PoolParty\.git/ nocase ascii wide
                        $string8_PoolParty_offensive_tool_keyword = /\/PoolParty\.hpp/ nocase ascii wide
                        $string9_PoolParty_offensive_tool_keyword = /\/PoolParty\.sln/ nocase ascii wide
                        $string10_PoolParty_offensive_tool_keyword = /\/PoolParty\.vcxproj/ nocase ascii wide
                        $string11_PoolParty_offensive_tool_keyword = /\\HandleHijacker\.cpp/ nocase ascii wide
                        $string12_PoolParty_offensive_tool_keyword = /\\HandleHijacker\.hpp/ nocase ascii wide
                        $string13_PoolParty_offensive_tool_keyword = /\\PoolParty\.cpp/ nocase ascii wide
                        $string14_PoolParty_offensive_tool_keyword = /\\PoolParty\.exe/ nocase ascii wide
                        $string15_PoolParty_offensive_tool_keyword = /\\PoolParty\.hpp/ nocase ascii wide
                        $string16_PoolParty_offensive_tool_keyword = /\\PoolParty\.sln/ nocase ascii wide
                        $string17_PoolParty_offensive_tool_keyword = /\\PoolParty\.vcxproj/ nocase ascii wide
                        $string18_PoolParty_offensive_tool_keyword = /\\PoolParty\-PoolParty\\/ nocase ascii wide
                        $string19_PoolParty_offensive_tool_keyword = /\\x24\\xC3\\C\:\\\\Windows\\\\System32\\\\calc\.exe\\x00/ nocase ascii wide
                        $string20_PoolParty_offensive_tool_keyword = "45D59D79-EF51-4A93-AAFA-2879FFC3A62C" nocase ascii wide
                        $string21_PoolParty_offensive_tool_keyword = "Allocated shellcode memory in the target process: " nocase ascii wide
                        $string22_PoolParty_offensive_tool_keyword = "Hijacked timer queue handle from the target process: " nocase ascii wide
                        $string23_PoolParty_offensive_tool_keyword = "Hijacked worker factory handle from the target process: " nocase ascii wide
                        $string24_PoolParty_offensive_tool_keyword = "PoolParty attack completed successfully" nocase ascii wide
                        $string25_PoolParty_offensive_tool_keyword = /PoolParty\.exe\s/ nocase ascii wide
                        $string26_PoolParty_offensive_tool_keyword = /PoolParty\-main\.zip/ nocase ascii wide
                        $string27_PoolParty_offensive_tool_keyword = /PoolParty\-PoolParty\.zip/ nocase ascii wide
                        $string28_PoolParty_offensive_tool_keyword = "SafeBreach-Labs/PoolParty" nocase ascii wide
                        $string29_PoolParty_offensive_tool_keyword = "Starting PoolParty attack against process id: " nocase ascii wide
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