rule Pspersist
{
    meta:
        description = "Detection patterns for the tool 'Pspersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pspersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PSpersist\.git/ nocase ascii wide
                        $string2 = /\\PSprofile\.exe/ nocase ascii wide
                        $string3 = "436b7f540f534a0ec1337cf82a76cb7727acda423132195f0c81560cdf75c438" nocase ascii wide
                        $string4 = "58482e19d6376bbe0120289b6d39a35de15b68d00713f821ab0c7f28f85a31ee" nocase ascii wide
                        $string5 = "5A403F3C-9136-4B67-A94E-02D3BCD3162D" nocase ascii wide
                        $string6 = "Pspersist-main" nocase ascii wide
                        $string7 = /PSprofile\.cpp/ nocase ascii wide
                        $string8 = /Start\sMenu\\Programs\\Startup\\Loader\.exe/ nocase ascii wide
                        $string9 = "TheD1rkMtr/Pspersist" nocase ascii wide

    condition:
        any of them
}