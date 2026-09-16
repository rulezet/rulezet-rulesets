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
                        $string16 = /http\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
                        $string17 = /http\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/ nocase ascii wide
                        $string18 = /https\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
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

    condition:
        any of them
}