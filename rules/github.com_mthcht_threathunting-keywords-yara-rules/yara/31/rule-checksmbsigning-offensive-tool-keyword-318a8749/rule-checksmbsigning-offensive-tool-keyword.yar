rule rule_CheckSMBSigning_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CheckSMBSigning' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheckSMBSigning"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CheckSMBSigning_offensive_tool_keyword = /\sCheckSMBSigning\.ps1/ nocase ascii wide
                        $string2_CheckSMBSigning_offensive_tool_keyword = /\sGet\-SMBSigning\.ps1/ nocase ascii wide
                        $string3_CheckSMBSigning_offensive_tool_keyword = /\/CheckSMBSigning\.git/ nocase ascii wide
                        $string4_CheckSMBSigning_offensive_tool_keyword = /\/CheckSMBSigning\.ps1/ nocase ascii wide
                        $string5_CheckSMBSigning_offensive_tool_keyword = /\/Get\-SMBSigning\.ps1/ nocase ascii wide
                        $string6_CheckSMBSigning_offensive_tool_keyword = /\\CheckSMBSigning\.ps1/ nocase ascii wide
                        $string7_CheckSMBSigning_offensive_tool_keyword = /\\Get\-SMBSigning\.ps1/ nocase ascii wide
                        $string8_CheckSMBSigning_offensive_tool_keyword = /\\SMBSigningNotRequired\.txt/ nocase ascii wide
                        $string9_CheckSMBSigning_offensive_tool_keyword = "2b38b8acc2d37042c0f5c2a8932f59ce8d5556103a54f2665a648476d214cc45" nocase ascii wide
                        $string10_CheckSMBSigning_offensive_tool_keyword = "CheckSMBSigning -Targets " nocase ascii wide
                        $string11_CheckSMBSigning_offensive_tool_keyword = "Get-SMBSigning -DelayJitter " nocase ascii wide
                        $string12_CheckSMBSigning_offensive_tool_keyword = "Leo4j/CheckSMBSigning" nocase ascii wide
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