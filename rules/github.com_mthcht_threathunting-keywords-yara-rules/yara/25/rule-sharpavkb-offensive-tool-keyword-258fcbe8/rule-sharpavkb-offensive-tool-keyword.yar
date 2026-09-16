rule rule_SharpAVKB_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpAVKB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAVKB"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpAVKB_offensive_tool_keyword = " --> GetWindowsAnti-VirusSoftware" nocase ascii wide
                        $string2_SharpAVKB_offensive_tool_keyword = " --> GetWindowsKernelExploitsKB" nocase ascii wide
                        $string3_SharpAVKB_offensive_tool_keyword = /\/SharpAVKB\.exe/ nocase ascii wide
                        $string4_SharpAVKB_offensive_tool_keyword = /\/SharpAVKB\.git/ nocase ascii wide
                        $string5_SharpAVKB_offensive_tool_keyword = /\\SharpAVKB\.exe/ nocase ascii wide
                        $string6_SharpAVKB_offensive_tool_keyword = /\\SharpAVKB\.pdb/ nocase ascii wide
                        $string7_SharpAVKB_offensive_tool_keyword = /\\SharpAVKB\-master/ nocase ascii wide
                        $string8_SharpAVKB_offensive_tool_keyword = ">SharpAVKB<" nocase ascii wide
                        $string9_SharpAVKB_offensive_tool_keyword = "0771a4c0fcbe55ce0e36aa1af50febcf4c2e96643a281a8de703a28f88536434" nocase ascii wide
                        $string10_SharpAVKB_offensive_tool_keyword = "4bc0cedc1fa6de2b307d94dbb2bc90133a937d3fdf884a877565396e3fb0d027" nocase ascii wide
                        $string11_SharpAVKB_offensive_tool_keyword = "6098d11342a5c4da204bed3fb3f420ce4df1664eb68ff23a17e4898cb3a11e07" nocase ascii wide
                        $string12_SharpAVKB_offensive_tool_keyword = "99DDC600-3E6F-435E-89DF-74439FA68061" nocase ascii wide
                        $string13_SharpAVKB_offensive_tool_keyword = "ed5c0c94ccd4fb0029dbfc609f8fc57580856648a188f595134f12c28ed97490" nocase ascii wide
                        $string14_SharpAVKB_offensive_tool_keyword = "edd2c3b117bf18e520fc98063528a003b8958a15f731fe7646cfab0b433bf69d" nocase ascii wide
                        $string15_SharpAVKB_offensive_tool_keyword = "f26f806ab5bce710cc598cc1623c2094e06b36548240c5db136d7e6d32ccbae5" nocase ascii wide
                        $string16_SharpAVKB_offensive_tool_keyword = /SharpAVKB\.Cmd/ nocase ascii wide
                        $string17_SharpAVKB_offensive_tool_keyword = /SharpAVKB\.exe\s\-AV/ nocase ascii wide
                        $string18_SharpAVKB_offensive_tool_keyword = "uknowsec/SharpAVKB" nocase ascii wide
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