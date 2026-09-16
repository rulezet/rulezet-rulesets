rule rule_webtrufflehog_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'webtrufflehog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webtrufflehog"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_webtrufflehog_offensive_tool_keyword = /\/com\.webtrufflehog\.json/ nocase ascii wide
                        $string2_webtrufflehog_offensive_tool_keyword = /\/webtrufflehog\.git/ nocase ascii wide
                        $string3_webtrufflehog_offensive_tool_keyword = /\/webtrufflehog\.log/ nocase ascii wide
                        $string4_webtrufflehog_offensive_tool_keyword = /\\webtrufflehog\.log/ nocase ascii wide
                        $string5_webtrufflehog_offensive_tool_keyword = /\\webtrufflehog\-main/ nocase ascii wide
                        $string6_webtrufflehog_offensive_tool_keyword = "450746e51e6f1369e7e73c5e2122d0ca81153d3a4c7bcec3d66266b15ee547f7" nocase ascii wide
                        $string7_webtrufflehog_offensive_tool_keyword = "52b6c057a9e0af822cbe129053d2c2d3541bf6e9ef162432fae60fdbd7a2d0f0" nocase ascii wide
                        $string8_webtrufflehog_offensive_tool_keyword = "85239f4abe215e87a147a6f63e8a281c2c3a687dcc45d430042c1e897de36696" nocase ascii wide
                        $string9_webtrufflehog_offensive_tool_keyword = "922d41ca55d3fa150f1c8fdc1f030e2acf6c24fcbd0ce1cd1021aeffe29bf24c" nocase ascii wide
                        $string10_webtrufflehog_offensive_tool_keyword = "akoofbljmjeodfmdpjndmmnifglppjdi" nocase ascii wide
                        $string11_webtrufflehog_offensive_tool_keyword = "c3l3si4n/webtrufflehog" nocase ascii wide
                        $string12_webtrufflehog_offensive_tool_keyword = "d62a0e8ea863d3812dcbf3927534db6b2a82223f2bfd2c374c7263be98b855f1" nocase ascii wide
                        $string13_webtrufflehog_offensive_tool_keyword = /scan_with_trufflehog\(/ nocase ascii wide
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