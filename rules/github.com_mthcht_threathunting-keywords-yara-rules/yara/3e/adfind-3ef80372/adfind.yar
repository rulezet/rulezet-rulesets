rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " dclist " nocase ascii wide
                        $string2 = /\s\-f\s\\"\(objectcategory\=computer\)\\"\s\-s\ssubtree\sdn\soperatingSystem/ nocase ascii wide
                        $string3 = /\s\-f\s\\"\(objectcategory\=person\)\\"\s\-s\ssubtree\ssamaccountname\suserPrincipalName/ nocase ascii wide
                        $string4 = /\s\-f\s\\"\(objectcategory\=trustedDomain\)\\"\s\-s\ssubtree\sname\strustAttributes\strustDirection\strustType/ nocase ascii wide
                        $string5 = " -sc getacls -sddlfilter " nocase ascii wide
                        $string6 = " -sc trustdump" nocase ascii wide
                        $string7 = /\.exe\s\-gcb\s\-sc\strustdmp\s\>\s/ nocase ascii wide
                        $string8 = /\.exe\s\-sc\sadinfo\s\>\s/ nocase ascii wide
                        $string9 = /\.exe\s\-sc\sdclist\s\>\s/ nocase ascii wide
                        $string10 = /\.exe\s\-sc\sgetacls\s\-sddlfilter\s/ nocase ascii wide
                        $string11 = /\.exe\s\-sc\strustdmp\s\>\s/ nocase ascii wide
                        $string12 = /\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s/ nocase ascii wide
                        $string13 = /\/AdFind\.zip/ nocase ascii wide
                        $string14 = /\\adf\.bat/ nocase ascii wide
                        $string15 = /\\adfind\.cf/ nocase ascii wide
                        $string16 = /\\AdFind\.zip/ nocase ascii wide
                        $string17 = ">AdFind<" nocase ascii wide
                        $string18 = "20b1918318148e410159d729ffcc373932073e2a68e993cc4440fc7df214471d" nocase ascii wide
                        $string19 = "484dd00e85c033fbfd506b956ac0acd29b30f239755ed753a2788a842425b384" nocase ascii wide
                        $string20 = "776a81b705827758d8810b9985a23ac59dc4cfd7ac616f0f08373d188d8291e6" nocase ascii wide
                        $string21 = "8f4662a487860ced024b2b38e6386a97ff7986313778a54a559eb0fc52e98606" nocase ascii wide
                        $string22 = "93c99378e20e88a9b81826b6619fde2bf261b278cfc2cdb79697a1575f9120fc" nocase ascii wide
                        $string23 = "adfind -f " nocase ascii wide
                        $string24 = "adfind -f objectclass=trusteddomain" nocase ascii wide
                        $string25 = "adfind -sc trustdmp" nocase ascii wide
                        $string26 = /adfind\.bat/ nocase ascii wide
                        $string27 = /adfind\.exe\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
                        $string28 = /adfind\.exe\s\-sc\strustdmp/ nocase ascii wide
                        $string29 = /adfind\.exe/ nocase ascii wide
                        $string30 = /AdFind\\AdFind\.cpp/ nocase ascii wide
                        $string31 = /AdFind_original\.exe/ nocase ascii wide
                        $string32 = "ce7c494c2959f874740bab1c74b444d776c9d6550337c8c046a1ddd795194b98" nocase ascii wide
                        $string33 = "computers_pwdnotreqd" nocase ascii wide
                        $string34 = /joeware_default_adfind\.cf/ nocase ascii wide
                        $string35 = "tools/adfind" nocase ascii wide

    condition:
        any of them
}