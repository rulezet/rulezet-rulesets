rule rule_ShadowStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShadowStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShadowStealer_offensive_tool_keyword = /\/amsiwala\.exe/ nocase ascii wide
                        $string2_ShadowStealer_offensive_tool_keyword = /\/ShadowStealer\.git/ nocase ascii wide
                        $string3_ShadowStealer_offensive_tool_keyword = /\\amsiwala\.exe/ nocase ascii wide
                        $string4_ShadowStealer_offensive_tool_keyword = /\\ShadowStealer\.csproj/ nocase ascii wide
                        $string5_ShadowStealer_offensive_tool_keyword = /\\ShadowStealer\.csproj/ nocase ascii wide
                        $string6_ShadowStealer_offensive_tool_keyword = /\\ShadowStealer\.sln/ nocase ascii wide
                        $string7_ShadowStealer_offensive_tool_keyword = /\\ShadowStealer\\/ nocase ascii wide
                        $string8_ShadowStealer_offensive_tool_keyword = /\\stolen_cookies\.txt/ nocase ascii wide
                        $string9_ShadowStealer_offensive_tool_keyword = "42914217da8d5f50f1eb540af6b49433fbfbe42f598bb4ecd162ef2c88d07f1f" nocase ascii wide
                        $string10_ShadowStealer_offensive_tool_keyword = "447b74994f6fec7bf3118b9c2056feca43667b899889c2a4f561303a18c82ce9" nocase ascii wide
                        $string11_ShadowStealer_offensive_tool_keyword = "4e82ec92f2cd6fd2a1f62c874170a00ec419bae8ad713f2ec1d3a25ad1746693" nocase ascii wide
                        $string12_ShadowStealer_offensive_tool_keyword = "7186796941:AAHmCxfhfQvNwDAtlvAmGY-N9c5sFXhHpNM" nocase ascii wide
                        $string13_ShadowStealer_offensive_tool_keyword = "87beb1086bd0d4b1a6e66fa634eadcbf379c7fae17967f61b8cf97fad6bb4887" nocase ascii wide
                        $string14_ShadowStealer_offensive_tool_keyword = "a07dd62cf32175dc33bd37663dd3c89eef9413c805ad448e0e5a252b5cb5527f" nocase ascii wide
                        $string15_ShadowStealer_offensive_tool_keyword = "ab48a8d28e53fb65d460c4faa8cc44d8e00c9684b7fb4dd2598223d7e2963da6" nocase ascii wide
                        $string16_ShadowStealer_offensive_tool_keyword = "Cookies stolen and saved successfully!\"" nocase ascii wide
                        $string17_ShadowStealer_offensive_tool_keyword = "F835A9E7-2542-45C2-9D85-EC0C9FDFFB16" nocase ascii wide
                        $string18_ShadowStealer_offensive_tool_keyword = /https\:\/\/\{server\}\.gofile\.io\/uploadFile/ nocase ascii wide
                        $string19_ShadowStealer_offensive_tool_keyword = "Passwords stolen and saved successfully!" nocase ascii wide
                        $string20_ShadowStealer_offensive_tool_keyword = /ShadowStealer\.zip/ nocase ascii wide
                        $string21_ShadowStealer_offensive_tool_keyword = /stolen_passwords\.txt/ nocase ascii wide
                        $string22_ShadowStealer_offensive_tool_keyword = "xelroth/ShadowStealer" nocase ascii wide
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