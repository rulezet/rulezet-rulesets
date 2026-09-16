rule sshamble
{
    meta:
        description = "Detection patterns for the tool 'sshamble' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshamble"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/sshamble\.git/ nocase ascii wide
                        $string2 = "/usr/local/bin/sshamble"
                        $string3 = "375f1c3e957ea3eea4956ae449e652962a57473ff55f193b8eabec033eeea187" nocase ascii wide
                        $string4 = "78a924220cf74c45f237414aa61e73f066f175f0cc47649dc0668769941ed305" nocase ascii wide
                        $string5 = "9e2e7dd4185ca2abe91139c009790c2a8991e8c652ef8b0d80989a4070c764f0" nocase ascii wide
                        $string6 = /https\:\/\/badkeys\.info\// nocase ascii wide
                        $string7 = /https\:\/\/SSHamble\.com\// nocase ascii wide
                        $string8 = "runZeroInc/sshamble" nocase ascii wide
                        $string9 = "sshamble scan " nocase ascii wide
                        $string10 = /sshamble.{0,100}badkeys/ nocase ascii wide
                        $string11 = "sshamble/badkeys" nocase ascii wide
                        $string12 = /sshamble\-main\.zip/ nocase ascii wide
                        $string13 = "threatpatrols/sshamble" nocase ascii wide
                        $string14 = "userenum-password-timing" nocase ascii wide
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