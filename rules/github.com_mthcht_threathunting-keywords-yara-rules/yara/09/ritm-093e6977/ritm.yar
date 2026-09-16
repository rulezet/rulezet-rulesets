rule RITM
{
    meta:
        description = "Detection patterns for the tool 'RITM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RITM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " import Spoofer, Sniffer, Roaster" nocase ascii wide
                        $string2 = /\sroaster\.py/ nocase ascii wide
                        $string3 = /\ssniffer\.py/ nocase ascii wide
                        $string4 = /\sspoofer\.py/ nocase ascii wide
                        $string5 = /\/RITM\.git/ nocase ascii wide
                        $string6 = /\/roaster\.py/
                        $string7 = /\/sniffer\.py/ nocase ascii wide
                        $string8 = /\/spoofer\.py/ nocase ascii wide
                        $string9 = /\\roaster\.py/ nocase ascii wide
                        $string10 = /\\sniffer\.py/ nocase ascii wide
                        $string11 = /\\spoofer\.py/ nocase ascii wide
                        $string12 = "387e21adbabeddf80db5d2868f93d6bdba8443dc26fdb964ec6e279f3d02310c" nocase ascii wide
                        $string13 = "ad393f135cc101f7897812ad3183775a89853e89cab5f31ae89eef3240ca9c4f" nocase ascii wide
                        $string14 = "f1525ffa97500a9aa64138541d1e91f403e494d8a6eef7bcb1f1de7e8261755e" nocase ascii wide
                        $string15 = /from\sritm\.lib\simport\s/ nocase ascii wide
                        $string16 = /from\sritm\.logger\simport\s/ nocase ascii wide
                        $string17 = /I\sneed\sroooot\.\sUnable\sto\sopen\s/ nocase ascii wide
                        $string18 = /impacket\.krb5\./ nocase ascii wide
                        $string19 = "poetry run ritm " nocase ascii wide
                        $string20 = "'Roasted SPN " nocase ascii wide
                        $string21 = "Sniffed AS-REQ from " nocase ascii wide
                        $string22 = "Sniffer waiting for AS-REQ" nocase ascii wide
                        $string23 = "The AS-REQ is valid! Attempting to roast " nocase ascii wide
                        $string24 = "Tw1sm/RITM" nocase ascii wide

    condition:
        any of them
}