rule rule_Cronos_Rootkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cronos-Rootkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cronos-Rootkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Cronos_Rootkit_offensive_tool_keyword = "- Cronos rootkit debugger -" nocase ascii wide
                        $string2_Cronos_Rootkit_offensive_tool_keyword = "/Cronos-Rootkit" nocase ascii wide
                        $string3_Cronos_Rootkit_offensive_tool_keyword = "/Cronos-Rootkit/" nocase ascii wide
                        $string4_Cronos_Rootkit_offensive_tool_keyword = /\/Cronos\-x64\.zip/ nocase ascii wide
                        $string5_Cronos_Rootkit_offensive_tool_keyword = /\\\\\\\\\.\\\\Cronos/ nocase ascii wide
                        $string6_Cronos_Rootkit_offensive_tool_keyword = /\\Cronos\sRootkit\.sln/ nocase ascii wide
                        $string7_Cronos_Rootkit_offensive_tool_keyword = /\\Cronos\sRootkit\\/ nocase ascii wide
                        $string8_Cronos_Rootkit_offensive_tool_keyword = /\\CronosDebugger\.vcxproj/ nocase ascii wide
                        $string9_Cronos_Rootkit_offensive_tool_keyword = /\\Cronos\-x64\.zip/ nocase ascii wide
                        $string10_Cronos_Rootkit_offensive_tool_keyword = /\\Rootkit\.cpp/ nocase ascii wide
                        $string11_Cronos_Rootkit_offensive_tool_keyword = "05B4EB7F-3D59-4E6A-A7BC-7C1241578CA7" nocase ascii wide
                        $string12_Cronos_Rootkit_offensive_tool_keyword = "1d9b4121c2dbc17a4db31341da2097cd430a61201c57185a42fb687f22f704eb" nocase ascii wide
                        $string13_Cronos_Rootkit_offensive_tool_keyword = "6f7949ffcf1b9bce2ab2301e6a75a4ba8690ea3434b74bd6c3ba0e9aca6d5d04" nocase ascii wide
                        $string14_Cronos_Rootkit_offensive_tool_keyword = "940B1177-2B8C-48A2-A8E7-BF4E8E80C60F" nocase ascii wide
                        $string15_Cronos_Rootkit_offensive_tool_keyword = /Cronos\sRootkit\./ nocase ascii wide
                        $string16_Cronos_Rootkit_offensive_tool_keyword = /CronosDebugger\./ nocase ascii wide
                        $string17_Cronos_Rootkit_offensive_tool_keyword = /CronosRootkit\./ nocase ascii wide
                        $string18_Cronos_Rootkit_offensive_tool_keyword = /Rootkit\.cpp/ nocase ascii wide
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