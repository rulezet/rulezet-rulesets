rule rule_MailPassView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MailPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MailPassView_offensive_tool_keyword = /\/mailpv\.exe/ nocase ascii wide
                        $string2_MailPassView_offensive_tool_keyword = /\/utils\/mailpv\.html/ nocase ascii wide
                        $string3_MailPassView_offensive_tool_keyword = /\\mailpv\.exe/ nocase ascii wide
                        $string4_MailPassView_offensive_tool_keyword = "18e9b39ab7c27ea80c6b76fc04881a5348de491ab22abe65a6bdb7254e23d5d1" nocase ascii wide
                        $string5_MailPassView_offensive_tool_keyword = "5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd" nocase ascii wide
                        $string6_MailPassView_offensive_tool_keyword = "5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd" nocase ascii wide
                        $string7_MailPassView_offensive_tool_keyword = "Email  Password-Recovery" nocase ascii wide
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