rule SpoolFool
{
    meta:
        description = "Detection patterns for the tool 'SpoolFool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpoolFool"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "A Variant Of Win64/AddUser" nocase ascii wide
                        $string2 = "ATK/SpoolFool-A" nocase ascii wide
                        $string3 = /Exp\.CVE\-2022\-21999/ nocase ascii wide
                        $string4 = /Exploit\.CVE202222718\.MSIL/ nocase ascii wide
                        $string5 = /Generic\.Exploit\.CVE\-2022\-22718\.A\.2798221A/ nocase ascii wide
                        $string6 = /HEUR\:Exploit\.MSIL\.CVE\-2022\-22718\.gen/ nocase ascii wide
                        $string7 = /MSIL\/CVE_2022_22718\.A\!exploit/ nocase ascii wide
                        $string8 = /MSIL\/Exploit\.CVE\-2022\-22718\.A/ nocase ascii wide
                        $string9 = /Trojan\.AddUser/ nocase ascii wide
                        $string10 = /VirTool\:MSIL\/Spfolz\.A\!MTB/ nocase ascii wide
                        $string11 = /Win\.Exploit\.Exploitx\-9942911\-0/ nocase ascii wide

    condition:
        any of them
}