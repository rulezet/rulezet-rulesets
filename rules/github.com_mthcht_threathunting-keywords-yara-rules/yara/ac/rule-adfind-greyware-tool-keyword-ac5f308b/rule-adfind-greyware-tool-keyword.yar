rule rule_adfind_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_adfind_greyware_tool_keyword = " dclist " nocase ascii wide
                        $string2_adfind_greyware_tool_keyword = /\s\-f\s\\"\(objectcategory\=computer\)\\"\s\-s\ssubtree\sdn\soperatingSystem/ nocase ascii wide
                        $string3_adfind_greyware_tool_keyword = /\s\-f\s\\"\(objectcategory\=person\)\\"\s\-s\ssubtree\ssamaccountname\suserPrincipalName/ nocase ascii wide
                        $string4_adfind_greyware_tool_keyword = /\s\-f\s\\"\(objectcategory\=trustedDomain\)\\"\s\-s\ssubtree\sname\strustAttributes\strustDirection\strustType/ nocase ascii wide
                        $string5_adfind_greyware_tool_keyword = " -sc getacls -sddlfilter " nocase ascii wide
                        $string6_adfind_greyware_tool_keyword = " -sc trustdump" nocase ascii wide
                        $string7_adfind_greyware_tool_keyword = /\.exe\s\-gcb\s\-sc\strustdmp\s\>\s/ nocase ascii wide
                        $string8_adfind_greyware_tool_keyword = /\.exe\s\-sc\sadinfo\s\>\s/ nocase ascii wide
                        $string9_adfind_greyware_tool_keyword = /\.exe\s\-sc\sdclist\s\>\s/ nocase ascii wide
                        $string10_adfind_greyware_tool_keyword = /\.exe\s\-sc\sgetacls\s\-sddlfilter\s/ nocase ascii wide
                        $string11_adfind_greyware_tool_keyword = /\.exe\s\-sc\strustdmp\s\>\s/ nocase ascii wide
                        $string12_adfind_greyware_tool_keyword = /\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s/ nocase ascii wide
                        $string13_adfind_greyware_tool_keyword = /\/AdFind\.zip/ nocase ascii wide
                        $string14_adfind_greyware_tool_keyword = /\\adf\.bat/ nocase ascii wide
                        $string15_adfind_greyware_tool_keyword = /\\adfind\.cf/ nocase ascii wide
                        $string16_adfind_greyware_tool_keyword = /\\AdFind\.zip/ nocase ascii wide
                        $string17_adfind_greyware_tool_keyword = ">AdFind<" nocase ascii wide
                        $string18_adfind_greyware_tool_keyword = "20b1918318148e410159d729ffcc373932073e2a68e993cc4440fc7df214471d" nocase ascii wide
                        $string19_adfind_greyware_tool_keyword = "484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384" nocase ascii wide
                        $string20_adfind_greyware_tool_keyword = "776a81b705827758d8810b9985a23ac59dc4cfd7ac616f0f08373d188d8291e6" nocase ascii wide
                        $string21_adfind_greyware_tool_keyword = "8f4662a487860ced024b2b38e6386a97ff7986313778a54a559eb0fc52e98606" nocase ascii wide
                        $string22_adfind_greyware_tool_keyword = "93c99378e20e88a9b81826b6619fde2bf261b278cfc2cdb79697a1575f9120fc" nocase ascii wide
                        $string23_adfind_greyware_tool_keyword = "adfind -f " nocase ascii wide
                        $string24_adfind_greyware_tool_keyword = "adfind -f objectclass=trusteddomain" nocase ascii wide
                        $string25_adfind_greyware_tool_keyword = "adfind -sc trustdmp" nocase ascii wide
                        $string26_adfind_greyware_tool_keyword = /adfind\.bat/ nocase ascii wide
                        $string27_adfind_greyware_tool_keyword = /adfind\.exe\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
                        $string28_adfind_greyware_tool_keyword = /adfind\.exe\s\-sc\strustdmp/ nocase ascii wide
                        $string29_adfind_greyware_tool_keyword = /adfind\.exe/ nocase ascii wide
                        $string30_adfind_greyware_tool_keyword = /AdFind\\AdFind\.cpp/ nocase ascii wide
                        $string31_adfind_greyware_tool_keyword = /AdFind_original\.exe/ nocase ascii wide
                        $string32_adfind_greyware_tool_keyword = "ce7c494c2959f874740bab1c74b444d776c9d6550337c8c046a1ddd795194b98" nocase ascii wide
                        $string33_adfind_greyware_tool_keyword = "computers_pwdnotreqd" nocase ascii wide
                        $string34_adfind_greyware_tool_keyword = /joeware_default_adfind\.cf/ nocase ascii wide
                        $string35_adfind_greyware_tool_keyword = "tools/adfind" nocase ascii wide

    condition:
        any of them
}