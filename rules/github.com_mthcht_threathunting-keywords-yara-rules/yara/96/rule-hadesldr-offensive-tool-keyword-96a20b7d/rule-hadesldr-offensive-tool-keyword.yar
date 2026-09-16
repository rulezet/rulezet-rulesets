rule rule_HadesLdr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HadesLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HadesLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HadesLdr_offensive_tool_keyword = /\s\-h\s.{0,100}\-p\s.{0,100}\s\-c\scypher\.bin\s\-k\skey\.bin/ nocase ascii wide
                        $string2_HadesLdr_offensive_tool_keyword = /\/HadesLdr\.git/ nocase ascii wide
                        $string3_HadesLdr_offensive_tool_keyword = /\/scripts\/xor\.py/ nocase ascii wide
                        $string4_HadesLdr_offensive_tool_keyword = "CognisysGroup/HadesLdr" nocase ascii wide
                        $string5_HadesLdr_offensive_tool_keyword = "HadesLdr-main" nocase ascii wide
                        $string6_HadesLdr_offensive_tool_keyword = /IDSyscall\.exe/ nocase ascii wide
                        $string7_HadesLdr_offensive_tool_keyword = /IDSyscall\.sln/ nocase ascii wide
                        $string8_HadesLdr_offensive_tool_keyword = /IDSyscall\.vcxproj/ nocase ascii wide
                        $string9_HadesLdr_offensive_tool_keyword = "IDSyscall/IDSyscall" nocase ascii wide
                        $string10_HadesLdr_offensive_tool_keyword = /IDSyscall\\IDSyscall/ nocase ascii wide
                        $string11_HadesLdr_offensive_tool_keyword = /python3\sGetHash\.py\sNtCreateFile/ nocase ascii wide
                        $string12_HadesLdr_offensive_tool_keyword = /rc4\.py\s.{0,100}\.bin/ nocase ascii wide
                        $string13_HadesLdr_offensive_tool_keyword = /syscallStuff\.asm/ nocase ascii wide
                        $string14_HadesLdr_offensive_tool_keyword = /xor\.py\s.{0,100}\.dll/ nocase ascii wide
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