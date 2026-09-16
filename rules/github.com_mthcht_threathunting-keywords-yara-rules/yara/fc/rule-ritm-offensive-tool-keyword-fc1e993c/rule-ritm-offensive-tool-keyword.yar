rule rule_RITM_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RITM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RITM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RITM_offensive_tool_keyword = " import Spoofer, Sniffer, Roaster" nocase ascii wide
                        $string2_RITM_offensive_tool_keyword = /\sroaster\.py/ nocase ascii wide
                        $string3_RITM_offensive_tool_keyword = /\ssniffer\.py/ nocase ascii wide
                        $string4_RITM_offensive_tool_keyword = /\sspoofer\.py/ nocase ascii wide
                        $string5_RITM_offensive_tool_keyword = /\/RITM\.git/ nocase ascii wide
                        $string6_RITM_offensive_tool_keyword = /\/roaster\.py/
                        $string7_RITM_offensive_tool_keyword = /\/sniffer\.py/ nocase ascii wide
                        $string8_RITM_offensive_tool_keyword = /\/spoofer\.py/ nocase ascii wide
                        $string9_RITM_offensive_tool_keyword = /\\roaster\.py/ nocase ascii wide
                        $string10_RITM_offensive_tool_keyword = /\\sniffer\.py/ nocase ascii wide
                        $string11_RITM_offensive_tool_keyword = /\\spoofer\.py/ nocase ascii wide
                        $string12_RITM_offensive_tool_keyword = "387e21adbabeddf80db5d2868f93d6bdba8443dc26fdb964ec6e279f3d02310c" nocase ascii wide
                        $string13_RITM_offensive_tool_keyword = "ad393f135cc101f7897812ad3183775a89853e89cab5f31ae89eef3240ca9c4f" nocase ascii wide
                        $string14_RITM_offensive_tool_keyword = "f1525ffa97500a9aa64138541d1e91f403e494d8a6eef7bcb1f1de7e8261755e" nocase ascii wide
                        $string15_RITM_offensive_tool_keyword = /from\sritm\.lib\simport\s/ nocase ascii wide
                        $string16_RITM_offensive_tool_keyword = /from\sritm\.logger\simport\s/ nocase ascii wide
                        $string17_RITM_offensive_tool_keyword = /I\sneed\sroooot\.\sUnable\sto\sopen\s/ nocase ascii wide
                        $string18_RITM_offensive_tool_keyword = /impacket\.krb5\./ nocase ascii wide
                        $string19_RITM_offensive_tool_keyword = "poetry run ritm " nocase ascii wide
                        $string20_RITM_offensive_tool_keyword = "'Roasted SPN " nocase ascii wide
                        $string21_RITM_offensive_tool_keyword = "Sniffed AS-REQ from " nocase ascii wide
                        $string22_RITM_offensive_tool_keyword = "Sniffer waiting for AS-REQ" nocase ascii wide
                        $string23_RITM_offensive_tool_keyword = "The AS-REQ is valid! Attempting to roast " nocase ascii wide
                        $string24_RITM_offensive_tool_keyword = "Tw1sm/RITM" nocase ascii wide

    condition:
        any of them
}