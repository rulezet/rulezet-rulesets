rule ShimMe
{
    meta:
        description = "Detection patterns for the tool 'ShimMe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShimMe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/OfficeInjector\.exe/ nocase ascii wide
                        $string2 = /\/ShimInjector\.exe/ nocase ascii wide
                        $string3 = /\/ShimMe\.git/ nocase ascii wide
                        $string4 = /\\\\\\\\\.\\\\pipe\\\\ElevationPipe/ nocase ascii wide
                        $string5 = /\\\\Debug\\\\Injected\.dll/ nocase ascii wide
                        $string6 = /\\\\Release\\\\Injected\.dll/ nocase ascii wide
                        $string7 = /\\\\temp\\\\Injected\.dll/ nocase ascii wide
                        $string8 = /\\Debug\\Injected\.dll/ nocase ascii wide
                        $string9 = /\\OfficeInjector\.exe/ nocase ascii wide
                        $string10 = /\\pipe\\ElevationPipe/ nocase ascii wide
                        $string11 = /\\Release\\Injected\.dll/ nocase ascii wide
                        $string12 = /\\ShimInjector\.cpp/ nocase ascii wide
                        $string13 = /\\ShimInjector\.cpp/ nocase ascii wide
                        $string14 = /\\ShimInjector\.exe/ nocase ascii wide
                        $string15 = /\\temp\\Injected\.dll/ nocase ascii wide
                        $string16 = "0286bd5f-1a56-4251-8758-adb0338d4e98" nocase ascii wide
                        $string17 = "036b5e87804f5996d8009b8d06f95a307227c6835a51ce64427cae7189cf86d2" nocase ascii wide
                        $string18 = "04a57cd7fa95b8851ef4d45aa6b30b9c89dbbbe7b8a1780a15c34b9a81f9ef91" nocase ascii wide
                        $string19 = "1605d453-7d62-4198-a436-27e48ef828eb" nocase ascii wide
                        $string20 = "220dea762dec11fe8d6a5b7a24b6af9e4b72dfc084e2b1b835ab661323486ecc" nocase ascii wide
                        $string21 = "6d93cc6c0eebf09311c01439395e8f02def87ffe8b4abf010ff5f8f18603f96c" nocase ascii wide
                        $string22 = "7afe06b8-59cc-41d2-9d75-65473ea93117" nocase ascii wide
                        $string23 = "8cb4a31c-11c4-49e4-8c7a-b9c6df93f5d8" nocase ascii wide
                        $string24 = "a1e4912be7e7d1db5247a326fec21f847d254d87ed253ad2b9de085a66d5eb13" nocase ascii wide
                        $string25 = "deepinstinct/ShimMe" nocase ascii wide
                        $string26 = /InjectDll\sRTVideo\.dll/ nocase ascii wide
                        $string27 = "SHIM me what you got - Manipulating Shim and Office for Code Injection" nocase ascii wide
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