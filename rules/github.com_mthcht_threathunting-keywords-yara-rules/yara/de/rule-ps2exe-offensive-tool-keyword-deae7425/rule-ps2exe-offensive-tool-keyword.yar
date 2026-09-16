rule rule_PS2EXE_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PS2EXE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PS2EXE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PS2EXE_offensive_tool_keyword = /\sPS2EXE\.ps1/ nocase ascii wide
                        $string2_PS2EXE_offensive_tool_keyword = /\/PS2EXE\.git/ nocase ascii wide
                        $string3_PS2EXE_offensive_tool_keyword = /\/PS2EXE\.ps1/ nocase ascii wide
                        $string4_PS2EXE_offensive_tool_keyword = "/PS2EXE/" nocase ascii wide
                        $string5_PS2EXE_offensive_tool_keyword = /\\PS2EXE\.ps1/ nocase ascii wide
                        $string6_PS2EXE_offensive_tool_keyword = /\\Win\-PS2EXE/ nocase ascii wide
                        $string7_PS2EXE_offensive_tool_keyword = "760c4649c5acd734d931ee64ebfc62eb19fa5c45137f4712b84aba7a356cda91" nocase ascii wide
                        $string8_PS2EXE_offensive_tool_keyword = "Install-Module ps2exe" nocase ascii wide
                        $string9_PS2EXE_offensive_tool_keyword = "Invoke-ps2exe" nocase ascii wide
                        $string10_PS2EXE_offensive_tool_keyword = "Leo4j/PS2EXE" nocase ascii wide
                        $string11_PS2EXE_offensive_tool_keyword = "MScholtes/PS2EXE" nocase ascii wide
                        $string12_PS2EXE_offensive_tool_keyword = /ps\.AddScript\(Encoding\.UTF8\.GetString\(Convert\.FromBase64String\(script\)/ nocase ascii wide
                        $string13_PS2EXE_offensive_tool_keyword = /PS1ToEXE.{0,100}PS2EXE\.ps1/ nocase ascii wide
                        $string14_PS2EXE_offensive_tool_keyword = "ps2exe -" nocase ascii wide
                        $string15_PS2EXE_offensive_tool_keyword = /ps2exe\s.{0,100}\.ps1.{0,100}\.exe/ nocase ascii wide
                        $string16_PS2EXE_offensive_tool_keyword = /PS2EXE\s\-content\s\$.{0,100}\s\-outputFile\s/ nocase ascii wide
                        $string17_PS2EXE_offensive_tool_keyword = /ps2exe\.ps1/ nocase ascii wide
                        $string18_PS2EXE_offensive_tool_keyword = /ps2exe\.psd1/ nocase ascii wide
                        $string19_PS2EXE_offensive_tool_keyword = /ps2exe\.psm1/ nocase ascii wide
                        $string20_PS2EXE_offensive_tool_keyword = "PS2EXE-master" nocase ascii wide
                        $string21_PS2EXE_offensive_tool_keyword = /Win\-PS2EXE\.exe/ nocase ascii wide
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