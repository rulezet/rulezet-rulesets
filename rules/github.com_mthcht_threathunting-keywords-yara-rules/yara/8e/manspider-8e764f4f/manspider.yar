rule MANSPIDER
{
    meta:
        description = "Detection patterns for the tool 'MANSPIDER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MANSPIDER"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --dirnames bank financ payable payment reconcil remit voucher vendor eft swift " nocase ascii wide
                        $string2 = " -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config " nocase ascii wide
                        $string3 = " -e pfx p12 pkcs12 pem key crt cer csr jks keystore key keys der " nocase ascii wide
                        $string4 = " -e ppk rsa pem ssh rsa" nocase ascii wide
                        $string5 = " -f passw -e xlsx csv " nocase ascii wide
                        $string6 = " -f passw user admin account network login logon cred " nocase ascii wide
                        $string7 = /\/\.manspider\/logs/
                        $string8 = /\/\.manspider\/loot/
                        $string9 = /\/MANSPIDER\.git/ nocase ascii wide
                        $string10 = /\/manspider_.{0,1000}\.log/
                        $string11 = /\/tmp\/\.manspider/
                        $string12 = /\\manspider_.{0,1000}\.log/ nocase ascii wide
                        $string13 = "blacklanternsecurity/MANSPIDER" nocase ascii wide
                        $string14 = /man_spider\.manspider\:main/ nocase ascii wide
                        $string15 = /manspider\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string16 = /manspider\s.{0,1000}\/24\s\-f\s/ nocase ascii wide
                        $string17 = /manspider.{0,1000}\-\-loot\-dir/ nocase ascii wide
                        $string18 = /manspider.{0,1000}\-\-sharenames/ nocase ascii wide
                        $string19 = /manspider\.py/ nocase ascii wide
                        $string20 = /manspider\.spiderling/ nocase ascii wide
                        $string21 = "MANSPIDER-master" nocase ascii wide

    condition:
        any of them
}