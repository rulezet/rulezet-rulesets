rule rule_ngrok_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ngrok' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ngrok"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ngrok_greyware_tool_keyword = /\.ngrok\.me/ nocase ascii wide
                        $string2_ngrok_greyware_tool_keyword = /\/ngrok\.exe/ nocase ascii wide
                        $string3_ngrok_greyware_tool_keyword = /\/ngrok\.git/ nocase ascii wide
                        $string4_ngrok_greyware_tool_keyword = /\/ngrok\.go/ nocase ascii wide
                        $string5_ngrok_greyware_tool_keyword = /\/ngrok\.log/
                        $string6_ngrok_greyware_tool_keyword = /\/ngrokd\.go/ nocase ascii wide
                        $string7_ngrok_greyware_tool_keyword = /\/ngrokroot\.crt/
                        $string8_ngrok_greyware_tool_keyword = /\\ngrok\.exe/ nocase ascii wide
                        $string9_ngrok_greyware_tool_keyword = /\\ngrok\.go/ nocase ascii wide
                        $string10_ngrok_greyware_tool_keyword = /\\ngrok\.log/ nocase ascii wide
                        $string11_ngrok_greyware_tool_keyword = /\\ngrok\\config\.yml/ nocase ascii wide
                        $string12_ngrok_greyware_tool_keyword = /\\ngrok\\ng\.psm1/ nocase ascii wide
                        $string13_ngrok_greyware_tool_keyword = /\\ngrokd\.go/ nocase ascii wide
                        $string14_ngrok_greyware_tool_keyword = "6abfc342f0a659066c8b42999510ccc3592b499569c2e7af37470a445a2e3560" nocase ascii wide
                        $string15_ngrok_greyware_tool_keyword = "fe9dd722a085bce94fe2403f8d02e20becf0f0faa019d0789fadf35b66611a46" nocase ascii wide
                        $string16_ngrok_greyware_tool_keyword = /http\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
                        $string17_ngrok_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/ nocase ascii wide
                        $string18_ngrok_greyware_tool_keyword = /https\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
                        $string19_ngrok_greyware_tool_keyword = "inconshreveable/ngrok" nocase ascii wide
                        $string20_ngrok_greyware_tool_keyword = /LHOST\=0\.tcp\.ngrok\.io/ nocase ascii wide
                        $string21_ngrok_greyware_tool_keyword = /Mozilla\/5\.0\s\(compatible\;\sngrok\)/ nocase ascii wide
                        $string22_ngrok_greyware_tool_keyword = "ngrok tcp " nocase ascii wide
                        $string23_ngrok_greyware_tool_keyword = /ngrok\,\sInc\./ nocase ascii wide
                        $string24_ngrok_greyware_tool_keyword = /ngrokd\.ngrok\.com/ nocase ascii wide
                        $string25_ngrok_greyware_tool_keyword = /tcp\:\/\/0\.tcp\.ngrok\.io\:/ nocase ascii wide
                        $string26_ngrok_greyware_tool_keyword = /tunnel\.ap\.ngrok\.com/ nocase ascii wide
                        $string27_ngrok_greyware_tool_keyword = /tunnel\.au\.ngrok\.com/ nocase ascii wide
                        $string28_ngrok_greyware_tool_keyword = /tunnel\.eu\.ngrok\.com/ nocase ascii wide
                        $string29_ngrok_greyware_tool_keyword = /tunnel\.in\.ngrok\.com/ nocase ascii wide
                        $string30_ngrok_greyware_tool_keyword = /tunnel\.jp\.ngrok\.com/ nocase ascii wide
                        $string31_ngrok_greyware_tool_keyword = /tunnel\.sa\.ngrok\.com/ nocase ascii wide
                        $string32_ngrok_greyware_tool_keyword = /tunnel\.us\.ngrok\.com/ nocase ascii wide

    condition:
        any of them
}