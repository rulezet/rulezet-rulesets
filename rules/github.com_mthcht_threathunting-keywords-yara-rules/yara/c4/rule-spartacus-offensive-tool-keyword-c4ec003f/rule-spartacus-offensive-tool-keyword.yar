rule rule_Spartacus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Spartacus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spartacus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Spartacus_offensive_tool_keyword = /\s\-\-action\sexports\s\-\-dll\sC\:\\Windows\\System32\\amsi\.dll/ nocase ascii wide
                        $string2_Spartacus_offensive_tool_keyword = /\s\-\-dll\s.{0,100}\s\-\-only\s.{0,100}AmsiScanBuffer.{0,100}AmsiScanString/ nocase ascii wide
                        $string3_Spartacus_offensive_tool_keyword = /\s\-\-dll\sC\:\\Windows\\System32\\version\.dll.{0,100}\-\-dll\sC\:\\Windows\\System32\\userenv\.dll/ nocase ascii wide
                        $string4_Spartacus_offensive_tool_keyword = /\s\-\-mode\sproxy\s\-\-ghidra\s.{0,100}\-\-dll\s/ nocase ascii wide
                        $string5_Spartacus_offensive_tool_keyword = /\\tmp\\dll\-collection/ nocase ascii wide
                        $string6_Spartacus_offensive_tool_keyword = "Accenture/Spartacus" nocase ascii wide
                        $string7_Spartacus_offensive_tool_keyword = /Assets\/solution\/dllmain\.cpp/ nocase ascii wide
                        $string8_Spartacus_offensive_tool_keyword = /Data\\VulnerableCOM\.csv/ nocase ascii wide
                        $string9_Spartacus_offensive_tool_keyword = /exports\s\-\-dll\s.{0,100}\.dll\s\-\-prototypes\s\.\/Assets\/prototypes\.csv/
                        $string10_Spartacus_offensive_tool_keyword = /help\\dll\.txt/ nocase ascii wide
                        $string11_Spartacus_offensive_tool_keyword = "--mode com --acl --csv " nocase ascii wide
                        $string12_Spartacus_offensive_tool_keyword = "--mode com --procmon " nocase ascii wide
                        $string13_Spartacus_offensive_tool_keyword = "--mode dll --existing --pml " nocase ascii wide
                        $string14_Spartacus_offensive_tool_keyword = "--mode dll --procmon " nocase ascii wide
                        $string15_Spartacus_offensive_tool_keyword = /\-\-mode\sproxy\s\-\-action\sprototypes\s\-\-path\s.{0,100}prototypes\.csv/ nocase ascii wide
                        $string16_Spartacus_offensive_tool_keyword = /\-\-mode\sproxy\s\-\-dll\s.{0,100}\.dll.{0,100}\-\-external\-resources/ nocase ascii wide
                        $string17_Spartacus_offensive_tool_keyword = /\-\-mode\sproxy\s\-\-ghidra\s.{0,100}\-\-dll\s/ nocase ascii wide
                        $string18_Spartacus_offensive_tool_keyword = /Spartacus\.exe\s\-\-mode\sproxy/ nocase ascii wide
                        $string19_Spartacus_offensive_tool_keyword = /Spartacus\-main\.zip/ nocase ascii wide
                        $string20_Spartacus_offensive_tool_keyword = /spartacus\-proxy\-.{0,100}\.log/ nocase ascii wide
                        $string21_Spartacus_offensive_tool_keyword = /Spartacus\-v2\..{0,100}\-x64\.zip/ nocase ascii wide
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