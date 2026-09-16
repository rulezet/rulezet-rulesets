rule rule_DecryptTeamViewer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DecryptTeamViewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptTeamViewer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DecryptTeamViewer_offensive_tool_keyword = /\/DecryptTeamViewer\.exe/ nocase ascii wide
                        $string2_DecryptTeamViewer_offensive_tool_keyword = /\/DecryptTeamViewer\.git/ nocase ascii wide
                        $string3_DecryptTeamViewer_offensive_tool_keyword = /\\DecryptTeamViewer\.exe/ nocase ascii wide
                        $string4_DecryptTeamViewer_offensive_tool_keyword = /\\DecryptTeamViewer\.sln/ nocase ascii wide
                        $string5_DecryptTeamViewer_offensive_tool_keyword = /\\DecryptTeamViewer\-master/ nocase ascii wide
                        $string6_DecryptTeamViewer_offensive_tool_keyword = "4aa99dcaf5030b1c4c7c57edd0fea22ab6db79caff79a547cc07572077631646" nocase ascii wide
                        $string7_DecryptTeamViewer_offensive_tool_keyword = "7ec9b36feeace5d4903be2adb2e1454af948a393c311b5513bfad0e9995b87e7" nocase ascii wide
                        $string8_DecryptTeamViewer_offensive_tool_keyword = "D6AAED62-BBFC-4F2A-A2A4-35EC5B2A4E07" nocase ascii wide
                        $string9_DecryptTeamViewer_offensive_tool_keyword = "DecryptTeamViewer: Pillaging registry for TeamViewer information" nocase ascii wide
                        $string10_DecryptTeamViewer_offensive_tool_keyword = /DecryptTeamViewer\-master\.zip/ nocase ascii wide
                        $string11_DecryptTeamViewer_offensive_tool_keyword = "V1V1/DecryptTeamViewer" nocase ascii wide
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