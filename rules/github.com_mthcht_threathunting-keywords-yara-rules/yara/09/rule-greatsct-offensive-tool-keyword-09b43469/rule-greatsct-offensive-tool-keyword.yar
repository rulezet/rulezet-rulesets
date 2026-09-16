rule rule_GreatSCT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GreatSCT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GreatSCT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GreatSCT_offensive_tool_keyword = /\s\-c\s.{0,100}OBFUSCATION\=.{0,100}\.ps1/ nocase ascii wide
                        $string2_GreatSCT_offensive_tool_keyword = " GreatSCT/" nocase ascii wide
                        $string3_GreatSCT_offensive_tool_keyword = " --list-payloads" nocase ascii wide
                        $string4_GreatSCT_offensive_tool_keyword = " --msfoptions " nocase ascii wide
                        $string5_GreatSCT_offensive_tool_keyword = "/Bypass/payloads" nocase ascii wide
                        $string6_GreatSCT_offensive_tool_keyword = "/GreatSCT/" nocase ascii wide
                        $string7_GreatSCT_offensive_tool_keyword = "/GreatSCT/GreatSCT"
                        $string8_GreatSCT_offensive_tool_keyword = "/greatsct-output" nocase ascii wide
                        $string9_GreatSCT_offensive_tool_keyword = "/regsvcs/meterpreter" nocase ascii wide
                        $string10_GreatSCT_offensive_tool_keyword = "/regsvr32/shellcode_inject" nocase ascii wide
                        $string11_GreatSCT_offensive_tool_keyword = "func_get_powershell_dll" nocase ascii wide
                        $string12_GreatSCT_offensive_tool_keyword = "func_install_wine_dotnettojscript" nocase ascii wide
                        $string13_GreatSCT_offensive_tool_keyword = "GreatSCT" nocase ascii wide
                        $string14_GreatSCT_offensive_tool_keyword = /GreatSCT\.git/ nocase ascii wide
                        $string15_GreatSCT_offensive_tool_keyword = /GreatSCT\.py/ nocase ascii wide
                        $string16_GreatSCT_offensive_tool_keyword = /invoke_obfuscation\.py/ nocase ascii wide
                        $string17_GreatSCT_offensive_tool_keyword = "--msfvenom " nocase ascii wide
                        $string18_GreatSCT_offensive_tool_keyword = "mshta/shellcode_inject" nocase ascii wide
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