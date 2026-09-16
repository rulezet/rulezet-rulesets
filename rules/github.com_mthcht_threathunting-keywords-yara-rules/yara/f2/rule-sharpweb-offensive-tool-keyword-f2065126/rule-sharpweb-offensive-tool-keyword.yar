rule rule_SharpWeb_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpWeb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpWeb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpWeb_offensive_tool_keyword = /\.exe\s\-b\schromium\s\-p\s.{0,100}\\AppData\\Local\\Google\\Chrome\\/ nocase ascii wide
                        $string2_SharpWeb_offensive_tool_keyword = /\/SharpWeb\.exe/ nocase ascii wide
                        $string3_SharpWeb_offensive_tool_keyword = /\/SharpWeb\.git/ nocase ascii wide
                        $string4_SharpWeb_offensive_tool_keyword = /\\SharpWeb\.exe/ nocase ascii wide
                        $string5_SharpWeb_offensive_tool_keyword = /\\SharpWeb\.sln/ nocase ascii wide
                        $string6_SharpWeb_offensive_tool_keyword = ">SharpWeb<" nocase ascii wide
                        $string7_SharpWeb_offensive_tool_keyword = "1c309b473a4221fa7bbb5566935f888a7d8cf523ea33c6f7b568c7342f81419a" nocase ascii wide
                        $string8_SharpWeb_offensive_tool_keyword = "1e2744c89803f6afc884b214ba4a8f47dfc1725a4180d767630205feeead064b" nocase ascii wide
                        $string9_SharpWeb_offensive_tool_keyword = "91292bac-72b4-4aab-9e5f-2bc1843c8ea3" nocase ascii wide
                        $string10_SharpWeb_offensive_tool_keyword = "99292BAC-72B4-4AAB-9E5F-2BC1843C8EA3" nocase ascii wide
                        $string11_SharpWeb_offensive_tool_keyword = "AE844C23-294E-4690-8CF3-2E5F9769D8E0" nocase ascii wide
                        $string12_SharpWeb_offensive_tool_keyword = /decrypt_chrome_v20_cookie\.py/ nocase ascii wide
                        $string13_SharpWeb_offensive_tool_keyword = /SharpWeb\.exe\s\-/ nocase ascii wide
                        $string14_SharpWeb_offensive_tool_keyword = "StarfireLab/SharpWeb" nocase ascii wide
                        $string15_SharpWeb_offensive_tool_keyword = "sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=" nocase ascii wide
                        $string16_SharpWeb_offensive_tool_keyword = /vaultSchema\.Add\(new\sGuid\(\\"\\"4BF4C442\-9B8A\-41A0\-B380\-DD4A704DDB28\\"\\"/ nocase ascii wide
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