rule rule_CursedChrome_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CursedChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CursedChrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CursedChrome_offensive_tool_keyword = /\/CursedChrome\.git/ nocase ascii wide
                        $string2_CursedChrome_offensive_tool_keyword = /\/extension_injection\.sh/ nocase ascii wide
                        $string3_CursedChrome_offensive_tool_keyword = /\/redirect\-hack\.html\?id\=/ nocase ascii wide
                        $string4_CursedChrome_offensive_tool_keyword = /127\.0\.0\.1\:8118/ nocase ascii wide
                        $string5_CursedChrome_offensive_tool_keyword = "A new browser has connected to us via WebSocket!" nocase ascii wide
                        $string6_CursedChrome_offensive_tool_keyword = /bash\sextension_injection\.sh/
                        $string7_CursedChrome_offensive_tool_keyword = "const subscription_id = `TOPROXY_" nocase ascii wide
                        $string8_CursedChrome_offensive_tool_keyword = /COPY\sanyproxy\/\s\.\/anyproxy\//
                        $string9_CursedChrome_offensive_tool_keyword = "CursedChrome API server is now listening on port" nocase ascii wide
                        $string10_CursedChrome_offensive_tool_keyword = "CursedChrome WebSocket server is now running on port" nocase ascii wide
                        $string11_CursedChrome_offensive_tool_keyword = /CursedChrome\-master\.zip/ nocase ascii wide
                        $string12_CursedChrome_offensive_tool_keyword = "DATABASE_PASSWORD: cursedchrome" nocase ascii wide
                        $string13_CursedChrome_offensive_tool_keyword = "DATABASE_USER: cursedchrome" nocase ascii wide
                        $string14_CursedChrome_offensive_tool_keyword = /docker\simages\s\|\sgrep\scursed/ nocase ascii wide
                        $string15_CursedChrome_offensive_tool_keyword = /docker\sps\s\-a\s\|\sgrep\scursed/ nocase ascii wide
                        $string16_CursedChrome_offensive_tool_keyword = "docker-compose up cursedchrome" nocase ascii wide
                        $string17_CursedChrome_offensive_tool_keyword = "http://localhost:8118" nocase ascii wide
                        $string18_CursedChrome_offensive_tool_keyword = /logit\(\`New\ssubscriber\:\sTOBROWSER__/ nocase ascii wide
                        $string19_CursedChrome_offensive_tool_keyword = "mandatoryprogrammer/CursedChrome" nocase ascii wide
                        $string20_CursedChrome_offensive_tool_keyword = /new\sWebSocket\(\\"ws\:\/\/127\.0\.0\.1\:4343\\"\)/ nocase ascii wide
                        $string21_CursedChrome_offensive_tool_keyword = /publisher\.publish\(\`TOBROWSER_/ nocase ascii wide
                        $string22_CursedChrome_offensive_tool_keyword = /Wat\,\sthis\sshouldn\'t\shappen\?\sOrphaned\smessage\s\(somebody\smight\sbe\sprobing\syou\!\)\:/ nocase ascii wide
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