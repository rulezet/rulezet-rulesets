rule rule_ShellPwnsh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShellPwnsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellPwnsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShellPwnsh_offensive_tool_keyword = /\.\/ShellPwnsh/
                        $string2_ShellPwnsh_offensive_tool_keyword = /\/ShellPwnsh\.git/ nocase ascii wide
                        $string3_ShellPwnsh_offensive_tool_keyword = /\\ShellPwnsh\-main/ nocase ascii wide
                        $string4_ShellPwnsh_offensive_tool_keyword = "32c3b62e05eb08f482b00ca28bca9b43d743048f287e9b42193df91d6ddcd09a" nocase ascii wide
                        $string5_ShellPwnsh_offensive_tool_keyword = "7e40488e6ce8545eccdcfd13124e609ff74c50a9ce89bc88b9b2b50862efda9c" nocase ascii wide
                        $string6_ShellPwnsh_offensive_tool_keyword = "9374f1f361c8c664f4527cc9e43e277fddab0bfc032e254fec9b22405210f808" nocase ascii wide
                        $string7_ShellPwnsh_offensive_tool_keyword = "BlackShell256/ShellPwnsh" nocase ascii wide
                        $string8_ShellPwnsh_offensive_tool_keyword = /FUD\sPayload\sGenerator\sby\sBlack\$hell256/ nocase ascii wide
                        $string9_ShellPwnsh_offensive_tool_keyword = /Generador\sde\sPayloads\sFUD\sby\sBlack\$hell256/ nocase ascii wide
                        $string10_ShellPwnsh_offensive_tool_keyword = /ShellPwnsh\.exe/ nocase ascii wide
                        $string11_ShellPwnsh_offensive_tool_keyword = /ShellPwnsh\.go/ nocase ascii wide
                        $string12_ShellPwnsh_offensive_tool_keyword = /System\.Net\.\$\(\[Text\.Encoding\]\:\:Unicode\.GetString\(\[Convert\]\:\:FromBase64String\(/ nocase ascii wide
                        $string13_ShellPwnsh_offensive_tool_keyword = /\'UwBvAGM\'\;\s\$xd\s\=\s\'AawBlA\'/ nocase ascii wide
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