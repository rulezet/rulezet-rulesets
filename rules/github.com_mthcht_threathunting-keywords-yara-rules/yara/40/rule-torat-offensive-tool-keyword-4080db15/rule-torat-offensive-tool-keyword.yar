rule rule_ToRat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ToRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ToRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ToRat_offensive_tool_keyword = "/dist:/dist_ext torat"
                        $string2_ToRat_offensive_tool_keyword = /\/persist_cortana\.py/ nocase ascii wide
                        $string3_ToRat_offensive_tool_keyword = /\/persist_people\.py/ nocase ascii wide
                        $string4_ToRat_offensive_tool_keyword = /\/persit_linux\.go/
                        $string5_ToRat_offensive_tool_keyword = /\/persit_windows\.go/ nocase ascii wide
                        $string6_ToRat_offensive_tool_keyword = /\/ToRat\.git/ nocase ascii wide
                        $string7_ToRat_offensive_tool_keyword = /\/tor\-static\-windows\-amd64\.zip/ nocase ascii wide
                        $string8_ToRat_offensive_tool_keyword = /\\persist_cortana\.py/ nocase ascii wide
                        $string9_ToRat_offensive_tool_keyword = /\\persist_people\.py/ nocase ascii wide
                        $string10_ToRat_offensive_tool_keyword = /\\persit_linux\.go/ nocase ascii wide
                        $string11_ToRat_offensive_tool_keyword = /\\persit_windows\.go/ nocase ascii wide
                        $string12_ToRat_offensive_tool_keyword = /\\ToRat\\cmd\\/ nocase ascii wide
                        $string13_ToRat_offensive_tool_keyword = /\\ToRat\\keygen\\/ nocase ascii wide
                        $string14_ToRat_offensive_tool_keyword = /\\ToRat\\torat_client\\/ nocase ascii wide
                        $string15_ToRat_offensive_tool_keyword = /\\ToRat\\torat_server\\/ nocase ascii wide
                        $string16_ToRat_offensive_tool_keyword = /\\ToRat\-master\.zip/ nocase ascii wide
                        $string17_ToRat_offensive_tool_keyword = /\\tor\-static\-windows\-amd64\.zip/ nocase ascii wide
                        $string18_ToRat_offensive_tool_keyword = /docker\sbuild\s\.\s\-t\storat/ nocase ascii wide
                        $string19_ToRat_offensive_tool_keyword = "docker run -it torat" nocase ascii wide
                        $string20_ToRat_offensive_tool_keyword = /localhost\:8000\/.{0,1000}\/hardware/ nocase ascii wide
                        $string21_ToRat_offensive_tool_keyword = /localhost\:8000\/.{0,1000}\/netscan/ nocase ascii wide
                        $string22_ToRat_offensive_tool_keyword = /localhost\:8000\/.{0,1000}\/osinfo/ nocase ascii wide
                        $string23_ToRat_offensive_tool_keyword = /localhost\:8000\/.{0,1000}\/speedtest/ nocase ascii wide
                        $string24_ToRat_offensive_tool_keyword = "lu4p/ToRat" nocase ascii wide
                        $string25_ToRat_offensive_tool_keyword = "server/ToRat_server" nocase ascii wide
                        $string26_ToRat_offensive_tool_keyword = "torEd25519" nocase ascii wide

    condition:
        any of them
}