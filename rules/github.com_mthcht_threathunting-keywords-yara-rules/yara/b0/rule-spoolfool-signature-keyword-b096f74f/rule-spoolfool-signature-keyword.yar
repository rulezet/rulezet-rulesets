rule rule_SpoolFool_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpoolFool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpoolFool"
        rule_category = "signature_keyword"

    strings:
                        $string1_SpoolFool_signature_keyword = "A Variant Of Win64/AddUser" nocase ascii wide
                        $string2_SpoolFool_signature_keyword = "ATK/SpoolFool-A" nocase ascii wide
                        $string3_SpoolFool_signature_keyword = /Exp\.CVE\-2022\-21999/ nocase ascii wide
                        $string4_SpoolFool_signature_keyword = /Exploit\.CVE202222718\.MSIL/ nocase ascii wide
                        $string5_SpoolFool_signature_keyword = /Generic\.Exploit\.CVE\-2022\-22718\.A\.2798221A/ nocase ascii wide
                        $string6_SpoolFool_signature_keyword = /HEUR\:Exploit\.MSIL\.CVE\-2022\-22718\.gen/ nocase ascii wide
                        $string7_SpoolFool_signature_keyword = /MSIL\/CVE_2022_22718\.A\!exploit/ nocase ascii wide
                        $string8_SpoolFool_signature_keyword = /MSIL\/Exploit\.CVE\-2022\-22718\.A/ nocase ascii wide
                        $string9_SpoolFool_signature_keyword = /Trojan\.AddUser/ nocase ascii wide
                        $string10_SpoolFool_signature_keyword = /VirTool\:MSIL\/Spfolz\.A\!MTB/ nocase ascii wide
                        $string11_SpoolFool_signature_keyword = /Win\.Exploit\.Exploitx\-9942911\-0/ nocase ascii wide

    condition:
        any of them
}