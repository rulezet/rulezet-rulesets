rule rule_ShimMe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShimMe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShimMe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShimMe_offensive_tool_keyword = /\/OfficeInjector\.exe/ nocase ascii wide
                        $string2_ShimMe_offensive_tool_keyword = /\/ShimInjector\.exe/ nocase ascii wide
                        $string3_ShimMe_offensive_tool_keyword = /\/ShimMe\.git/ nocase ascii wide
                        $string4_ShimMe_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\ElevationPipe/ nocase ascii wide
                        $string5_ShimMe_offensive_tool_keyword = /\\\\Debug\\\\Injected\.dll/ nocase ascii wide
                        $string6_ShimMe_offensive_tool_keyword = /\\\\Release\\\\Injected\.dll/ nocase ascii wide
                        $string7_ShimMe_offensive_tool_keyword = /\\\\temp\\\\Injected\.dll/ nocase ascii wide
                        $string8_ShimMe_offensive_tool_keyword = /\\Debug\\Injected\.dll/ nocase ascii wide
                        $string9_ShimMe_offensive_tool_keyword = /\\OfficeInjector\.exe/ nocase ascii wide
                        $string10_ShimMe_offensive_tool_keyword = /\\pipe\\ElevationPipe/ nocase ascii wide
                        $string11_ShimMe_offensive_tool_keyword = /\\Release\\Injected\.dll/ nocase ascii wide
                        $string12_ShimMe_offensive_tool_keyword = /\\ShimInjector\.cpp/ nocase ascii wide
                        $string13_ShimMe_offensive_tool_keyword = /\\ShimInjector\.cpp/ nocase ascii wide
                        $string14_ShimMe_offensive_tool_keyword = /\\ShimInjector\.exe/ nocase ascii wide
                        $string15_ShimMe_offensive_tool_keyword = /\\temp\\Injected\.dll/ nocase ascii wide
                        $string16_ShimMe_offensive_tool_keyword = "0286bd5f-1a56-4251-8758-adb0338d4e98" nocase ascii wide
                        $string17_ShimMe_offensive_tool_keyword = "036b5e87804f5996d8009b8d06f95a307227c6835a51ce64427cae7189cf86d2" nocase ascii wide
                        $string18_ShimMe_offensive_tool_keyword = "04a57cd7fa95b8851ef4d45aa6b30b9c89dbbbe7b8a1780a15c34b9a81f9ef91" nocase ascii wide
                        $string19_ShimMe_offensive_tool_keyword = "1605d453-7d62-4198-a436-27e48ef828eb" nocase ascii wide
                        $string20_ShimMe_offensive_tool_keyword = "220dea762dec11fe8d6a5b7a24b6af9e4b72dfc084e2b1b835ab661323486ecc" nocase ascii wide
                        $string21_ShimMe_offensive_tool_keyword = "6d93cc6c0eebf09311c01439395e8f02def87ffe8b4abf010ff5f8f18603f96c" nocase ascii wide
                        $string22_ShimMe_offensive_tool_keyword = "7afe06b8-59cc-41d2-9d75-65473ea93117" nocase ascii wide
                        $string23_ShimMe_offensive_tool_keyword = "8cb4a31c-11c4-49e4-8c7a-b9c6df93f5d8" nocase ascii wide
                        $string24_ShimMe_offensive_tool_keyword = "a1e4912be7e7d1db5247a326fec21f847d254d87ed253ad2b9de085a66d5eb13" nocase ascii wide
                        $string25_ShimMe_offensive_tool_keyword = "deepinstinct/ShimMe" nocase ascii wide
                        $string26_ShimMe_offensive_tool_keyword = /InjectDll\sRTVideo\.dll/ nocase ascii wide
                        $string27_ShimMe_offensive_tool_keyword = "SHIM me what you got - Manipulating Shim and Office for Code Injection" nocase ascii wide
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