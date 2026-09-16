rule TGT_Monitor
{
    meta:
        description = "Detection patterns for the tool 'TGT_Monitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TGT_Monitor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sTGT_Monitor\.ps1/ nocase ascii wide
                        $string2 = /\/TGT_Monitor\.git/ nocase ascii wide
                        $string3 = /\/TGT_Monitor\.ps1/ nocase ascii wide
                        $string4 = /\\TGT_Monitor\.ps1/ nocase ascii wide
                        $string5 = "1004ed17f2164c6dd249f7d640e8c8250e6c47d9e4d2c8748becb05591a8539b" nocase ascii wide
                        $string6 = "Get-AesKeyFromPassphrase" nocase ascii wide
                        $string7 = "Leo4j/TGT_Monitor" nocase ascii wide
                        $string8 = "TGT_Monitor -EncryptionKey " nocase ascii wide
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