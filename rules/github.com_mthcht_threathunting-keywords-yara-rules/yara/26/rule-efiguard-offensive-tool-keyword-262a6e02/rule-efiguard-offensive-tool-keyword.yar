rule rule_EfiGuard_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EfiGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EfiGuard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EfiGuard_offensive_tool_keyword = /\sEfiDSEFix\.cpp/ nocase ascii wide
                        $string2_EfiGuard_offensive_tool_keyword = /\sUefiShell\.iso/ nocase ascii wide
                        $string3_EfiGuard_offensive_tool_keyword = /\/EfiDSEFix\.cpp/ nocase ascii wide
                        $string4_EfiGuard_offensive_tool_keyword = /\/EfiDSEFix\.exe/ nocase ascii wide
                        $string5_EfiGuard_offensive_tool_keyword = /\/EfiGuard\.sln/ nocase ascii wide
                        $string6_EfiGuard_offensive_tool_keyword = /\/EfiGuardDxe\.c/ nocase ascii wide
                        $string7_EfiGuard_offensive_tool_keyword = /\/UefiShell\.iso/ nocase ascii wide
                        $string8_EfiGuard_offensive_tool_keyword = /\\Boot\\EfiGuardDxe\.efi/ nocase ascii wide
                        $string9_EfiGuard_offensive_tool_keyword = /\\EfiDSEFix\.cpp/ nocase ascii wide
                        $string10_EfiGuard_offensive_tool_keyword = /\\EfiDSEFix\.exe/ nocase ascii wide
                        $string11_EfiGuard_offensive_tool_keyword = /\\EfiGuard\.sln/ nocase ascii wide
                        $string12_EfiGuard_offensive_tool_keyword = /\\EfiGuardDxe\.c/ nocase ascii wide
                        $string13_EfiGuard_offensive_tool_keyword = /\\EfiGuardDxe\.h/ nocase ascii wide
                        $string14_EfiGuard_offensive_tool_keyword = /\\EfiGuardDxe\\X64\\/ nocase ascii wide
                        $string15_EfiGuard_offensive_tool_keyword = /\\UefiShell\.iso/ nocase ascii wide
                        $string16_EfiGuard_offensive_tool_keyword = "0E4BAB8F-E6E0-47A8-8E99-8D451839967E" nocase ascii wide
                        $string17_EfiGuard_offensive_tool_keyword = "B2924789-9912-4B6F-8F7B-53240AC3BA0E" nocase ascii wide
                        $string18_EfiGuard_offensive_tool_keyword = "D7484EBA-6357-4D81-B355-066E28D5DF72" nocase ascii wide
                        $string19_EfiGuard_offensive_tool_keyword = /EfiDSEFix\.exe\s/ nocase ascii wide
                        $string20_EfiGuard_offensive_tool_keyword = "EFIGUARD_BACKDOOR_VARIABLE_NAME" nocase ascii wide
                        $string21_EfiGuard_offensive_tool_keyword = /EfiGuard\-v1\.1\.zip/ nocase ascii wide
                        $string22_EfiGuard_offensive_tool_keyword = /EfiGuard\-v1\.2\.zip/ nocase ascii wide
                        $string23_EfiGuard_offensive_tool_keyword = /EfiGuard\-v1\.3\.zip/ nocase ascii wide
                        $string24_EfiGuard_offensive_tool_keyword = /EfiGuard\-v1\.4\.zip/ nocase ascii wide
                        $string25_EfiGuard_offensive_tool_keyword = /EfiGuard\-v1\.5\.zip/ nocase ascii wide
                        $string26_EfiGuard_offensive_tool_keyword = /Protocol\/EfiGuard\.h/ nocase ascii wide
                        $string27_EfiGuard_offensive_tool_keyword = "roodkcaBdrauGifE" nocase ascii wide
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