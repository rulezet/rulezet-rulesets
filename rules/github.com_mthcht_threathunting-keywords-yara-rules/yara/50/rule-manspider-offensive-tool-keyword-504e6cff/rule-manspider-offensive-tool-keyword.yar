rule rule_MANSPIDER_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MANSPIDER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MANSPIDER"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MANSPIDER_offensive_tool_keyword = " --dirnames bank financ payable payment reconcil remit voucher vendor eft swift " nocase ascii wide
                        $string2_MANSPIDER_offensive_tool_keyword = " -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config " nocase ascii wide
                        $string3_MANSPIDER_offensive_tool_keyword = " -e pfx p12 pkcs12 pem key crt cer csr jks keystore key keys der " nocase ascii wide
                        $string4_MANSPIDER_offensive_tool_keyword = " -e ppk rsa pem ssh rsa" nocase ascii wide
                        $string5_MANSPIDER_offensive_tool_keyword = " -f passw -e xlsx csv " nocase ascii wide
                        $string6_MANSPIDER_offensive_tool_keyword = " -f passw user admin account network login logon cred " nocase ascii wide
                        $string7_MANSPIDER_offensive_tool_keyword = /\/\.manspider\/logs/
                        $string8_MANSPIDER_offensive_tool_keyword = /\/\.manspider\/loot/
                        $string9_MANSPIDER_offensive_tool_keyword = /\/MANSPIDER\.git/ nocase ascii wide
                        $string10_MANSPIDER_offensive_tool_keyword = /\/manspider_.{0,1000}\.log/
                        $string11_MANSPIDER_offensive_tool_keyword = /\/tmp\/\.manspider/
                        $string12_MANSPIDER_offensive_tool_keyword = /\\manspider_.{0,1000}\.log/ nocase ascii wide
                        $string13_MANSPIDER_offensive_tool_keyword = "blacklanternsecurity/MANSPIDER" nocase ascii wide
                        $string14_MANSPIDER_offensive_tool_keyword = /man_spider\.manspider\:main/ nocase ascii wide
                        $string15_MANSPIDER_offensive_tool_keyword = /manspider\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string16_MANSPIDER_offensive_tool_keyword = /manspider\s.{0,1000}\/24\s\-f\s/ nocase ascii wide
                        $string17_MANSPIDER_offensive_tool_keyword = /manspider.{0,1000}\-\-loot\-dir/ nocase ascii wide
                        $string18_MANSPIDER_offensive_tool_keyword = /manspider.{0,1000}\-\-sharenames/ nocase ascii wide
                        $string19_MANSPIDER_offensive_tool_keyword = /manspider\.py/ nocase ascii wide
                        $string20_MANSPIDER_offensive_tool_keyword = /manspider\.spiderling/ nocase ascii wide
                        $string21_MANSPIDER_offensive_tool_keyword = "MANSPIDER-master" nocase ascii wide

    condition:
        any of them
}