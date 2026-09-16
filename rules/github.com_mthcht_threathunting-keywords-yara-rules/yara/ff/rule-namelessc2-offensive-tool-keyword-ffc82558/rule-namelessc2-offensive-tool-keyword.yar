rule rule_NamelessC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NamelessC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NamelessC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NamelessC2_offensive_tool_keyword = /\sConvertToShellcode\.py/ nocase ascii wide
                        $string2_NamelessC2_offensive_tool_keyword = /\sNamelessLog\.txt/ nocase ascii wide
                        $string3_NamelessC2_offensive_tool_keyword = /\/ConvertToShellcode\.py/ nocase ascii wide
                        $string4_NamelessC2_offensive_tool_keyword = /\/NamelessC2\.git/ nocase ascii wide
                        $string5_NamelessC2_offensive_tool_keyword = /\/NamelessLog\.txt/
                        $string6_NamelessC2_offensive_tool_keyword = /\[\+\]\sNameless\sTerminal/ nocase ascii wide
                        $string7_NamelessC2_offensive_tool_keyword = /\[\+\]\sStarting\sNameless\sServer/ nocase ascii wide
                        $string8_NamelessC2_offensive_tool_keyword = /\\ConvertToShellcode\.py/ nocase ascii wide
                        $string9_NamelessC2_offensive_tool_keyword = /\\NamelessC2\./ nocase ascii wide
                        $string10_NamelessC2_offensive_tool_keyword = /\\NamelessLog\.txt/ nocase ascii wide
                        $string11_NamelessC2_offensive_tool_keyword = "1e6f328bb3ca446969f0cf086b873081a5345b49fbb5f0bac9f7e5077cd74f76" nocase ascii wide
                        $string12_NamelessC2_offensive_tool_keyword = "7925b74698a6b8c9a8c0135a6fca700c610b8f97245b61d2949bc2b78c2f74fc" nocase ascii wide
                        $string13_NamelessC2_offensive_tool_keyword = "fcf42661023c6669ed49ee885c76f3edd3b04dedd6e1489d06aa2595c5ae60cc" nocase ascii wide
                        $string14_NamelessC2_offensive_tool_keyword = "from ShellcodeRDI import " nocase ascii wide
                        $string15_NamelessC2_offensive_tool_keyword = "Halo's Gate and Tartarus' Gate Patch for `syscall` instruction rather than `SSN`" nocase ascii wide
                        $string16_NamelessC2_offensive_tool_keyword = "MIIFFDCCAvwCCQDBhPvYPqGG4jANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJH" nocase ascii wide
                        $string17_NamelessC2_offensive_tool_keyword = "MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQDCRidsrTMB3NRW" nocase ascii wide
                        $string18_NamelessC2_offensive_tool_keyword = /NamelessImplant\.dll/ nocase ascii wide
                        $string19_NamelessC2_offensive_tool_keyword = /namelessserver\.com/ nocase ascii wide
                        $string20_NamelessC2_offensive_tool_keyword = "NamelessTerminal <OperatorName> <alive/all>" nocase ascii wide
                        $string21_NamelessC2_offensive_tool_keyword = "trickster0/NamelessC2" nocase ascii wide
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