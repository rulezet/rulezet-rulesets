rule rule_HTTP_Shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HTTP-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HTTP-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HTTP_Shell_offensive_tool_keyword = /\/HTTP\-Client\.sh/
                        $string2_HTTP_Shell_offensive_tool_keyword = /\/HTTP\-Shell\.git/ nocase ascii wide
                        $string3_HTTP_Shell_offensive_tool_keyword = /\/ps2exe\.ps1/ nocase ascii wide
                        $string4_HTTP_Shell_offensive_tool_keyword = /\[\+\]\sDownloading\sPS2exe\sand\sgenerating\spayload/ nocase ascii wide
                        $string5_HTTP_Shell_offensive_tool_keyword = /\[\+\]\sUploading\sto\sPS2exe\sand\sgenerating\spayload/ nocase ascii wide
                        $string6_HTTP_Shell_offensive_tool_keyword = /\\HTTP\-Client\.ps1/ nocase ascii wide
                        $string7_HTTP_Shell_offensive_tool_keyword = /\\HTTP\-Server\.py/ nocase ascii wide
                        $string8_HTTP_Shell_offensive_tool_keyword = /\\PayloadGen\.ps1/ nocase ascii wide
                        $string9_HTTP_Shell_offensive_tool_keyword = /\\ps2exe\.ps1/ nocase ascii wide
                        $string10_HTTP_Shell_offensive_tool_keyword = "185d6eb2bb3eeef1bc1737f766942e215342c864bdfd6132c2d55f22a5a10d61" nocase ascii wide
                        $string11_HTTP_Shell_offensive_tool_keyword = "340ebf838dd969bc96dde3068e57e62b30726e78bc663ef60ad6cbd7c5d8716a" nocase ascii wide
                        $string12_HTTP_Shell_offensive_tool_keyword = "7d67b3f5a0eae10e93d144bd9dba056c77d14b3246aa86ca20d8de02b3f1c674" nocase ascii wide
                        $string13_HTTP_Shell_offensive_tool_keyword = "f43e8c0cc98b12f28a0aa3548d67c78856c13292bfb06ecdfcbba5caefa9fef0" nocase ascii wide
                        $string14_HTTP_Shell_offensive_tool_keyword = /HTTP\-Server\.py\s/ nocase ascii wide
                        $string15_HTTP_Shell_offensive_tool_keyword = /invoke\-stealth\.php/ nocase ascii wide
                        $string16_HTTP_Shell_offensive_tool_keyword = /Invoke\-Stealth\.ps1/ nocase ascii wide
                        $string17_HTTP_Shell_offensive_tool_keyword = "JoelGMSec/HTTP-Shell" nocase ascii wide
                        $string18_HTTP_Shell_offensive_tool_keyword = /PayloadGen\sv2\.0\s\-\sby\s\@JoelGMSec/ nocase ascii wide
                        $string19_HTTP_Shell_offensive_tool_keyword = /Set\-Content\s\$PS2exePath/ nocase ascii wide
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