rule rule_SharpIncrease_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpIncrease' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpIncrease"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpIncrease_offensive_tool_keyword = /\/SharpIncrease\.exe/ nocase ascii wide
                        $string2_SharpIncrease_offensive_tool_keyword = /\/SharpIncrease\.git/ nocase ascii wide
                        $string3_SharpIncrease_offensive_tool_keyword = /\\SharpIncrease\.exe/ nocase ascii wide
                        $string4_SharpIncrease_offensive_tool_keyword = /\\SharpIncrease\.sln/ nocase ascii wide
                        $string5_SharpIncrease_offensive_tool_keyword = ">SharpIncrease<" nocase ascii wide
                        $string6_SharpIncrease_offensive_tool_keyword = "77849d97ebdb4c100d7195a3904fb6b829219bb9f8df46dd81151550546da532" nocase ascii wide
                        $string7_SharpIncrease_offensive_tool_keyword = "84075d23f3358b16e1f68b1eb56d34d34e88da9b29d504d36b5de2522cf6c23f" nocase ascii wide
                        $string8_SharpIncrease_offensive_tool_keyword = "B19E7FDE-C2CB-4C0A-9C5E-DFC73ADDB5C0" nocase ascii wide
                        $string9_SharpIncrease_offensive_tool_keyword = "f36ae1ef8fa544943bbd65f44d53fd994b42c91042e133c69019c66e73b20278" nocase ascii wide
                        $string10_SharpIncrease_offensive_tool_keyword = "mertdas/SharpIncrease" nocase ascii wide
                        $string11_SharpIncrease_offensive_tool_keyword = /SharpIncrease\.exe\s\-D\s/ nocase ascii wide
                        $string12_SharpIncrease_offensive_tool_keyword = /SharpIncrease\-main\.zip/ nocase ascii wide
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