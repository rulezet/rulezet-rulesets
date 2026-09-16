rule rule_HellsHall_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HellsHall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HellsHall"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HellsHall_offensive_tool_keyword = /\/HellHall\.git/ nocase ascii wide
                        $string2_HellsHall_offensive_tool_keyword = /\/HellsHall\.exe/ nocase ascii wide
                        $string3_HellsHall_offensive_tool_keyword = /\[\#\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sQUIT\s\.\.\.\s/ nocase ascii wide
                        $string4_HellsHall_offensive_tool_keyword = /\[\+\]\s\[HELL\sHALL\]\spAddress\s\:\s/ nocase ascii wide
                        $string5_HellsHall_offensive_tool_keyword = /\[i\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sRun\s\.\.\.\s/ nocase ascii wide
                        $string6_HellsHall_offensive_tool_keyword = /\\AsmHell\.asm/ nocase ascii wide
                        $string7_HellsHall_offensive_tool_keyword = /\\HellsHall\.c/ nocase ascii wide
                        $string8_HellsHall_offensive_tool_keyword = /\\HellsHall\.exe/ nocase ascii wide
                        $string9_HellsHall_offensive_tool_keyword = /\\HellsHall\.h/ nocase ascii wide
                        $string10_HellsHall_offensive_tool_keyword = "F06EAC7B-6996-4E78-B045-0DF6ED201367" nocase ascii wide
                        $string11_HellsHall_offensive_tool_keyword = /HellHall\-main\.zip/ nocase ascii wide
                        $string12_HellsHall_offensive_tool_keyword = /Hell\'sHall\.vcxproj/ nocase ascii wide
                        $string13_HellsHall_offensive_tool_keyword = /Hell\'sHall\-Clang\&NoCrt\.zip/ nocase ascii wide
                        $string14_HellsHall_offensive_tool_keyword = "Maldev-Academy/HellHall" nocase ascii wide
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