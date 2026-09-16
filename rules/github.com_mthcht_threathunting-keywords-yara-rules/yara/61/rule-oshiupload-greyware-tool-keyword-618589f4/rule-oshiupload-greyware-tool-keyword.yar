rule rule_OshiUpload_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OshiUpload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OshiUpload"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_OshiUpload_greyware_tool_keyword = /\soshi\.at\s/ nocase ascii wide
                        $string2_OshiUpload_greyware_tool_keyword = /\s\-\-socks5\-hostname\s127\.0\.0\.1\:9050/ nocase ascii wide
                        $string3_OshiUpload_greyware_tool_keyword = /\/oshi_run\.pl/
                        $string4_OshiUpload_greyware_tool_keyword = /\/OshiUpload\.git/ nocase ascii wide
                        $string5_OshiUpload_greyware_tool_keyword = /\[info\]\sTCP\supload\sserver\sstarted\s\(tcp\.pl\)/ nocase ascii wide
                        $string6_OshiUpload_greyware_tool_keyword = "1640fb593deccf72c27363463e6001a1ced831f423b00c8687555115f9365bec" nocase ascii wide
                        $string7_OshiUpload_greyware_tool_keyword = /5ety7tpkim5me6eszuwcje7bmy25pbtrjtue7zkqqgziljwqy3rrikqd\.onion/ nocase ascii wide
                        $string8_OshiUpload_greyware_tool_keyword = "ADMIN_BASICAUTH_PASSWORDHASH = f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7" nocase ascii wide
                        $string9_OshiUpload_greyware_tool_keyword = "ADMIN_ROUTE = /SuPeRsEcReTuRl/" nocase ascii wide
                        $string10_OshiUpload_greyware_tool_keyword = /https\:\/\/oshi\.at\// nocase ascii wide
                        $string11_OshiUpload_greyware_tool_keyword = /hypnotoad\s\-s\swebapp\.pl\s\&\&\ssleep\s5/ nocase ascii wide
                        $string12_OshiUpload_greyware_tool_keyword = /oshi\.at\/onion/ nocase ascii wide
                        $string13_OshiUpload_greyware_tool_keyword = /oshiatwowvdbshka\.onion/ nocase ascii wide
                        $string14_OshiUpload_greyware_tool_keyword = "OshiUpload/app" nocase ascii wide
                        $string15_OshiUpload_greyware_tool_keyword = /OshiUpload\-master\.zip/ nocase ascii wide
                        $string16_OshiUpload_greyware_tool_keyword = /reverse_proxy_tcp\.txt/ nocase ascii wide
                        $string17_OshiUpload_greyware_tool_keyword = "somenonymous/OshiUpload" nocase ascii wide

    condition:
        any of them
}