rule rule_dazzleUP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dazzleUP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dazzleUP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dazzleUP_offensive_tool_keyword = /\/dazzleUP\.git/ nocase ascii wide
                        $string2_dazzleUP_offensive_tool_keyword = /dazzleUP\.cna/ nocase ascii wide
                        $string3_dazzleUP_offensive_tool_keyword = /dazzleUP\.exe/ nocase ascii wide
                        $string4_dazzleUP_offensive_tool_keyword = /dazzleUP\.sln/ nocase ascii wide
                        $string5_dazzleUP_offensive_tool_keyword = /dazzleUP\.vcxproj/ nocase ascii wide
                        $string6_dazzleUP_offensive_tool_keyword = /dazzleUP\.x32\.exe/ nocase ascii wide
                        $string7_dazzleUP_offensive_tool_keyword = /dazzleUP\.x64\.exe/ nocase ascii wide
                        $string8_dazzleUP_offensive_tool_keyword = "dazzleUP_Reflective_DLL" nocase ascii wide
                        $string9_dazzleUP_offensive_tool_keyword = "dazzleUP-master" nocase ascii wide
                        $string10_dazzleUP_offensive_tool_keyword = "FE8F0D23-BDD1-416D-8285-F947BA86D155" nocase ascii wide
                        $string11_dazzleUP_offensive_tool_keyword = "hlldz/dazzleUP" nocase ascii wide
                        $string12_dazzleUP_offensive_tool_keyword = /path_dll_hijack\.h/ nocase ascii wide
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