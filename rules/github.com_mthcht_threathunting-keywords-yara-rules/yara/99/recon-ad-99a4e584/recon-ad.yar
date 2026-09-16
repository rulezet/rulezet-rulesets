rule Recon_AD
{
    meta:
        description = "Detection patterns for the tool 'Recon-AD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Recon-AD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Recon\-AD\.git/ nocase ascii wide
                        $string2 = /\/Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
                        $string3 = /\/Recon\-AD\-Computers\.dll/ nocase ascii wide
                        $string4 = /\/Recon\-AD\-Domain\.dll/ nocase ascii wide
                        $string5 = /\/Recon\-AD\-Groups\.dll/ nocase ascii wide
                        $string6 = /\/Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
                        $string7 = /\/Recon\-AD\-Users\.dll/ nocase ascii wide
                        $string8 = /\[\!\]\sCould\snot\sexecute\squery\.\sCould\snot\sbind\sto\sLDAP\:\/\/rootDSE\./ nocase ascii wide
                        $string9 = /\\Outflank\-Recon\-AD\\/ nocase ascii wide
                        $string10 = /\\Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
                        $string11 = /\\Recon\-AD\-AllLocalGroups\.sln/ nocase ascii wide
                        $string12 = /\\Recon\-AD\-AllLocalGroups\\/ nocase ascii wide
                        $string13 = /\\Recon\-AD\-Computers\.dll/ nocase ascii wide
                        $string14 = /\\Recon\-AD\-Computers\.sln/ nocase ascii wide
                        $string15 = /\\Recon\-AD\-Computers\\/ nocase ascii wide
                        $string16 = /\\Recon\-AD\-Domain\.dll/ nocase ascii wide
                        $string17 = /\\Recon\-AD\-Domain\.sln/ nocase ascii wide
                        $string18 = /\\Recon\-AD\-Domain\\/ nocase ascii wide
                        $string19 = /\\Recon\-AD\-Groups\.dll/ nocase ascii wide
                        $string20 = /\\Recon\-AD\-Groups\.sln/ nocase ascii wide
                        $string21 = /\\Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
                        $string22 = /\\Recon\-AD\-LocalGroups\.sln/ nocase ascii wide
                        $string23 = /\\Recon\-AD\-LocalGroups\\/ nocase ascii wide
                        $string24 = /\\Recon\-AD\-master/ nocase ascii wide
                        $string25 = /\\Recon\-AD\-SPNs\.sln/ nocase ascii wide
                        $string26 = /\\Recon\-AD\-SPNs\\/ nocase ascii wide
                        $string27 = /\\Recon\-AD\-Users\.dll/ nocase ascii wide
                        $string28 = /\\Recon\-AD\-Users\.sln/ nocase ascii wide
                        $string29 = /\\ReflectiveDll\.cpp/ nocase ascii wide
                        $string30 = /\\ReflectiveLoader\.cpp/ nocase ascii wide
                        $string31 = /\\Src\\Recon\-AD\-Groups\\/ nocase ascii wide
                        $string32 = /\\Src\\Recon\-AD\-Users\\/ nocase ascii wide
                        $string33 = "_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H" nocase ascii wide
                        $string34 = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" nocase ascii wide
                        $string35 = "outflanknl/Recon-AD" nocase ascii wide
                        $string36 = "Recon-AD-Computers All" nocase ascii wide
                        $string37 = "Recon-AD-Groups All" nocase ascii wide
                        $string38 = "Recon-AD-Users All" nocase ascii wide

    condition:
        any of them
}