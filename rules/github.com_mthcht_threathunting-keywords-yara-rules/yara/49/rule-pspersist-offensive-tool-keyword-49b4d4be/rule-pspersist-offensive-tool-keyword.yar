rule rule_Pspersist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pspersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pspersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pspersist_offensive_tool_keyword = /\/PSpersist\.git/ nocase ascii wide
                        $string2_Pspersist_offensive_tool_keyword = /\\PSprofile\.exe/ nocase ascii wide
                        $string3_Pspersist_offensive_tool_keyword = "436b7f540f534a0ec1337cf82a76cb7727acda423132195f0c81560cdf75c438" nocase ascii wide
                        $string4_Pspersist_offensive_tool_keyword = "58482e19d6376bbe0120289b6d39a35de15b68d00713f821ab0c7f28f85a31ee" nocase ascii wide
                        $string5_Pspersist_offensive_tool_keyword = "5A403F3C-9136-4B67-A94E-02D3BCD3162D" nocase ascii wide
                        $string6_Pspersist_offensive_tool_keyword = "Pspersist-main" nocase ascii wide
                        $string7_Pspersist_offensive_tool_keyword = /PSprofile\.cpp/ nocase ascii wide
                        $string8_Pspersist_offensive_tool_keyword = /Start\sMenu\\Programs\\Startup\\Loader\.exe/ nocase ascii wide
                        $string9_Pspersist_offensive_tool_keyword = "TheD1rkMtr/Pspersist" nocase ascii wide

    condition:
        any of them
}