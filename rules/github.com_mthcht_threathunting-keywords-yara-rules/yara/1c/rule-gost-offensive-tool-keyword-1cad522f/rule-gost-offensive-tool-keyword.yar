rule rule_gost_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gost"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gost_offensive_tool_keyword = /C\:\\Windows\\System\.exe.{0,100}\s\-L\srtcp\:\/\/0\.0\.0\.0\:8087\/127\.0\.0\.1\:4444\s\-F\ssocks5\:\/\/.{0,100}\:.{0,100}\@.{0,100}\:443/ nocase ascii wide
                        $string2_gost_offensive_tool_keyword = "ginuerzh/gost" nocase ascii wide
                        $string3_gost_offensive_tool_keyword = /gost\s\-L\=\:.{0,100}\s\-F\=.{0,100}\:/ nocase ascii wide
                        $string4_gost_offensive_tool_keyword = /gost\s\-L\=admin\:.{0,100}\@localhost\:/ nocase ascii wide
                        $string5_gost_offensive_tool_keyword = /gost\s\-L\=forward\+ssh\:\/\/\:/ nocase ascii wide
                        $string6_gost_offensive_tool_keyword = "gost -L=rtcp://" nocase ascii wide
                        $string7_gost_offensive_tool_keyword = "gost -L=rudp://" nocase ascii wide
                        $string8_gost_offensive_tool_keyword = "gost -L=ssh://:" nocase ascii wide
                        $string9_gost_offensive_tool_keyword = "gost -L=ssu://" nocase ascii wide
                        $string10_gost_offensive_tool_keyword = "gost -L=udp://" nocase ascii wide
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