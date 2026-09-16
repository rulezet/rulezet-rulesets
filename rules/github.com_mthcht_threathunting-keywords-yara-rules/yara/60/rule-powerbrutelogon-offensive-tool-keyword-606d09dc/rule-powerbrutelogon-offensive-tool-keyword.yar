rule rule_PowerBruteLogon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerBruteLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBruteLogon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerBruteLogon_offensive_tool_keyword = "/PowerBruteLogon" nocase ascii wide
                        $string2_PowerBruteLogon_offensive_tool_keyword = /\\PowerBruteLogon/ nocase ascii wide
                        $string3_PowerBruteLogon_offensive_tool_keyword = "3d686ba6d6985ff3febf3cd3d45cb5eb18eff45bfec74142865ded01f9c00503" nocase ascii wide
                        $string4_PowerBruteLogon_offensive_tool_keyword = "4b23fd7b0179a37fe15bf38ea9ccb0202202d36dcaa882c58a66c1979d37e92c" nocase ascii wide
                        $string5_PowerBruteLogon_offensive_tool_keyword = "5f8fdd73abce168e8b44db54ad203a66d4983d1fd2563bb5922c0aaef9abc4ea" nocase ascii wide
                        $string6_PowerBruteLogon_offensive_tool_keyword = "75682eac28a36100019a0606879be2a615e6c221b212833b2eb9ab83f6360cd6" nocase ascii wide
                        $string7_PowerBruteLogon_offensive_tool_keyword = "Invoke-BruteAvailableLogons" nocase ascii wide
                        $string8_PowerBruteLogon_offensive_tool_keyword = "Invoke-BruteLogonAccount" nocase ascii wide
                        $string9_PowerBruteLogon_offensive_tool_keyword = "Invoke-BruteLogonList" nocase ascii wide
                        $string10_PowerBruteLogon_offensive_tool_keyword = /PowerBruteLogon\./ nocase ascii wide
                        $string11_PowerBruteLogon_offensive_tool_keyword = /PowerBruteLogon\.zip/ nocase ascii wide
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