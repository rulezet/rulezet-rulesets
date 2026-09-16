rule PyPagekite
{
    meta:
        description = "Detection patterns for the tool 'PyPagekite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyPagekite"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " install xvnc4viewer netcat-traditional socat" nocase ascii wide
                        $string2 = /\spagekite\.logging/ nocase ascii wide
                        $string3 = /\spagekite\.py/ nocase ascii wide
                        $string4 = /\spagekite\-gtk\.py/ nocase ascii wide
                        $string5 = "\"PageKite system service\"" nocase ascii wide
                        $string6 = /\/etc\/pagekite\.d/
                        $string7 = /\/pagekite\-.{0,1000}\.log/
                        $string8 = /\/pagekite\.log/
                        $string9 = /\/pagekite\.py/ nocase ascii wide
                        $string10 = /\/pagekite\-0\.3\.21\.py/ nocase ascii wide
                        $string11 = /\/pagekite\-0\.4\.6a\.py/ nocase ascii wide
                        $string12 = /\/pagekite\-0\.5\.6d\.py/ nocase ascii wide
                        $string13 = /\/pagekite\-0\.5\.8a\.py/ nocase ascii wide
                        $string14 = /\/pagekite\-gtk\.py/ nocase ascii wide
                        $string15 = /\/pagekite\-tmp\.py/
                        $string16 = /\/PyPagekite\.git/ nocase ascii wide
                        $string17 = "/PyPagekite/tarball/" nocase ascii wide
                        $string18 = "/PyPagekite/zipball/" nocase ascii wide
                        $string19 = "/var/log/pagekite/"
                        $string20 = /\/var\/run\/pagekite\.pid/
                        $string21 = /\[PageKite\]\sRemote\sconnection\sclosed\!/ nocase ascii wide
                        $string22 = /\\pagekite\.cfg/ nocase ascii wide
                        $string23 = /\\pagekite\.py/ nocase ascii wide
                        $string24 = /\\pagekite\-gtk\.py/ nocase ascii wide
                        $string25 = "23e8d0a95d5769ea14e4fd5eac6b5c111ce538e61b18492c21482afd015170eb" nocase ascii wide
                        $string26 = "7270581d315cffb125f9ac64ebcb6622959c8e9f779b8a07808fd6929b0e746a" nocase ascii wide
                        $string27 = "7dc50c28dc7c2fa9a6ea80df35c06bd649b17ae86d333e88b3bf242ac5690c98" nocase ascii wide
                        $string28 = "b01db099512e344df190ee405619399c835b1d5522e2e6faa8e47b49418bab66" nocase ascii wide
                        $string29 = "be8fc36ec0082bdb7d20a21ae7098899529bc9b9f6439b1496ca634395598d8a" nocase ascii wide
                        $string30 = /bre\@pagekite\.net/ nocase ascii wide
                        $string31 = "c4ec5f4d04c44b7a1c8cf813435dbc66a541b450bbaca4d70ded985d6518e76a" nocase ascii wide
                        $string32 = "f16d1b7d69bf4c2a9a7e737809dd930012f419e7b7977887226f0f6859367cc4" nocase ascii wide
                        $string33 = "f2fd6676dba233df558278e6be42cd4c50a78a9c3f879db87acfc96607f41331" nocase ascii wide
                        $string34 = /http\:\/\/.{0,1000}\.pagekite\.me/ nocase ascii wide
                        $string35 = /http\:\/\/up\.pagekite\.net\// nocase ascii wide
                        $string36 = /https\:\/\/.{0,1000}\.pagekite\.me/ nocase ascii wide
                        $string37 = /https\:\/\/pagekite\.net\/downloads\// nocase ascii wide
                        $string38 = /https\:\/\/pagekite\.net\/pk\/src\// nocase ascii wide
                        $string39 = /kitename\.pagekite\.me/ nocase ascii wide
                        $string40 = /pagekite\.httpd/ nocase ascii wide
                        $string41 = /pagekite\.py\s\// nocase ascii wide
                        $string42 = /pagekite\.py\s443\shttps\:\/\// nocase ascii wide
                        $string43 = /pagekite\.py\s80\shttp\:\/\// nocase ascii wide
                        $string44 = /pagekite\.py\s\-\-add\s/ nocase ascii wide
                        $string45 = /pagekite\.py\slocalhost\:/ nocase ascii wide
                        $string46 = "pagekite/PyPagekite" nocase ascii wide

    condition:
        any of them
}