rule rule_PSRansom_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSRansom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRansom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSRansom_offensive_tool_keyword = " PopUpRansom" nocase ascii wide
                        $string2_PSRansom_offensive_tool_keyword = "/PSRansom -" nocase ascii wide
                        $string3_PSRansom_offensive_tool_keyword = /\\PSRansom\s\-/ nocase ascii wide
                        $string4_PSRansom_offensive_tool_keyword = "644e2fa03a4d45b8d0417819a7548339069df8d405131039006968b312c8c6f4" nocase ascii wide
                        $string5_PSRansom_offensive_tool_keyword = "C2Server by @JoelGMSec" nocase ascii wide
                        $string6_PSRansom_offensive_tool_keyword = /C2Server\.ps1/ nocase ascii wide
                        $string7_PSRansom_offensive_tool_keyword = "cf78b329b4dcb1c211415309e2ddbf80833ad1669fd142a67c916aa6a8cecb88" nocase ascii wide
                        $string8_PSRansom_offensive_tool_keyword = "JoelGMSec/PSRansom" nocase ascii wide
                        $string9_PSRansom_offensive_tool_keyword = "PSRansom by @JoelGMSec" nocase ascii wide
                        $string10_PSRansom_offensive_tool_keyword = /PSRansom\.ps1/ nocase ascii wide
                        $string11_PSRansom_offensive_tool_keyword = "pwd/C2Files/" nocase ascii wide
                        $string12_PSRansom_offensive_tool_keyword = /pwd\\C2Files\\/ nocase ascii wide
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