rule PoolParty
{
    meta:
        description = "Detection patterns for the tool 'PoolParty' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoolParty"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPoolParty\.cpp/ nocase ascii wide
                        $string2 = /\sPoolParty\.exe/ nocase ascii wide
                        $string3 = /\/HandleHijacker\.cpp/ nocase ascii wide
                        $string4 = /\/HandleHijacker\.hpp/ nocase ascii wide
                        $string5 = /\/PoolParty\.cpp/ nocase ascii wide
                        $string6 = /\/PoolParty\.exe/ nocase ascii wide
                        $string7 = /\/PoolParty\.git/ nocase ascii wide
                        $string8 = /\/PoolParty\.hpp/ nocase ascii wide
                        $string9 = /\/PoolParty\.sln/ nocase ascii wide
                        $string10 = /\/PoolParty\.vcxproj/ nocase ascii wide
                        $string11 = /\\HandleHijacker\.cpp/ nocase ascii wide
                        $string12 = /\\HandleHijacker\.hpp/ nocase ascii wide
                        $string13 = /\\PoolParty\.cpp/ nocase ascii wide
                        $string14 = /\\PoolParty\.exe/ nocase ascii wide
                        $string15 = /\\PoolParty\.hpp/ nocase ascii wide
                        $string16 = /\\PoolParty\.sln/ nocase ascii wide
                        $string17 = /\\PoolParty\.vcxproj/ nocase ascii wide
                        $string18 = /\\PoolParty\-PoolParty\\/ nocase ascii wide
                        $string19 = /\\x24\\xC3\\C\:\\\\Windows\\\\System32\\\\calc\.exe\\x00/ nocase ascii wide
                        $string20 = "45D59D79-EF51-4A93-AAFA-2879FFC3A62C" nocase ascii wide
                        $string21 = "Allocated shellcode memory in the target process: " nocase ascii wide
                        $string22 = "Hijacked timer queue handle from the target process: " nocase ascii wide
                        $string23 = "Hijacked worker factory handle from the target process: " nocase ascii wide
                        $string24 = "PoolParty attack completed successfully" nocase ascii wide
                        $string25 = /PoolParty\.exe\s/ nocase ascii wide
                        $string26 = /PoolParty\-main\.zip/ nocase ascii wide
                        $string27 = /PoolParty\-PoolParty\.zip/ nocase ascii wide
                        $string28 = "SafeBreach-Labs/PoolParty" nocase ascii wide
                        $string29 = "Starting PoolParty attack against process id: " nocase ascii wide
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