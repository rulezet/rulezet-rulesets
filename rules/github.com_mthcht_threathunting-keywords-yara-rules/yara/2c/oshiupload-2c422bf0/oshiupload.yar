rule OshiUpload
{
    meta:
        description = "Detection patterns for the tool 'OshiUpload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OshiUpload"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\soshi\.at\s/ nocase ascii wide
                        $string2 = /\s\-\-socks5\-hostname\s127\.0\.0\.1\:9050/ nocase ascii wide
                        $string3 = /\/oshi_run\.pl/
                        $string4 = /\/OshiUpload\.git/ nocase ascii wide
                        $string5 = /\[info\]\sTCP\supload\sserver\sstarted\s\(tcp\.pl\)/ nocase ascii wide
                        $string6 = "1640fb593deccf72c27363463e6001a1ced831f423b00c8687555115f9365bec" nocase ascii wide
                        $string7 = /5ety7tpkim5me6eszuwcje7bmy25pbtrjtue7zkqqgziljwqy3rrikqd\.onion/ nocase ascii wide
                        $string8 = "ADMIN_BASICAUTH_PASSWORDHASH = f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7" nocase ascii wide
                        $string9 = "ADMIN_ROUTE = /SuPeRsEcReTuRl/" nocase ascii wide
                        $string10 = /https\:\/\/oshi\.at\// nocase ascii wide
                        $string11 = /hypnotoad\s\-s\swebapp\.pl\s\&\&\ssleep\s5/ nocase ascii wide
                        $string12 = /oshi\.at\/onion/ nocase ascii wide
                        $string13 = /oshiatwowvdbshka\.onion/ nocase ascii wide
                        $string14 = "OshiUpload/app" nocase ascii wide
                        $string15 = /OshiUpload\-master\.zip/ nocase ascii wide
                        $string16 = /reverse_proxy_tcp\.txt/ nocase ascii wide
                        $string17 = "somenonymous/OshiUpload" nocase ascii wide

    condition:
        any of them
}