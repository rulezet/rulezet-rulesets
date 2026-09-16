rule ngrok
{
    meta:
        description = "Detection patterns for the tool 'ngrok' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ngrok"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.ngrok\.me/ nocase ascii wide
                        $string2 = /\/ngrok\.exe/ nocase ascii wide
                        $string3 = /\/ngrok\.git/ nocase ascii wide
                        $string4 = /\/ngrok\.go/ nocase ascii wide
                        $string5 = /\/ngrok\.log/
                        $string6 = /\/ngrokd\.go/ nocase ascii wide
                        $string7 = /\/ngrokroot\.crt/
                        $string8 = /\\ngrok\.exe/ nocase ascii wide
                        $string9 = /\\ngrok\.go/ nocase ascii wide
                        $string10 = /\\ngrok\.log/ nocase ascii wide
                        $string11 = /\\ngrok\\config\.yml/ nocase ascii wide
                        $string12 = /\\ngrok\\ng\.psm1/ nocase ascii wide
                        $string13 = /\\ngrokd\.go/ nocase ascii wide
                        $string14 = "6abfc342f0a659066c8b42999510ccc3592b499569c2e7af37470a445a2e3560" nocase ascii wide
                        $string15 = "fe9dd722a085bce94fe2403f8d02e20becf0f0faa019d0789fadf35b66611a46" nocase ascii wide
                        $string16 = /http\:\/\/.{0,100}\.ngrok\.io/ nocase ascii wide
                        $string17 = /http\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/ nocase ascii wide
                        $string18 = /https\:\/\/.{0,100}\.ngrok\.io/ nocase ascii wide
                        $string19 = "inconshreveable/ngrok" nocase ascii wide
                        $string20 = /LHOST\=0\.tcp\.ngrok\.io/ nocase ascii wide
                        $string21 = /Mozilla\/5\.0\s\(compatible\;\sngrok\)/ nocase ascii wide
                        $string22 = "ngrok tcp " nocase ascii wide
                        $string23 = /ngrok\,\sInc\./ nocase ascii wide
                        $string24 = /ngrokd\.ngrok\.com/ nocase ascii wide
                        $string25 = /tcp\:\/\/0\.tcp\.ngrok\.io\:/ nocase ascii wide
                        $string26 = /tunnel\.ap\.ngrok\.com/ nocase ascii wide
                        $string27 = /tunnel\.au\.ngrok\.com/ nocase ascii wide
                        $string28 = /tunnel\.eu\.ngrok\.com/ nocase ascii wide
                        $string29 = /tunnel\.in\.ngrok\.com/ nocase ascii wide
                        $string30 = /tunnel\.jp\.ngrok\.com/ nocase ascii wide
                        $string31 = /tunnel\.sa\.ngrok\.com/ nocase ascii wide
                        $string32 = /tunnel\.us\.ngrok\.com/ nocase ascii wide
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