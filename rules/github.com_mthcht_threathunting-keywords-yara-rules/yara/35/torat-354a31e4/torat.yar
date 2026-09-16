rule ToRat
{
    meta:
        description = "Detection patterns for the tool 'ToRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ToRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/dist:/dist_ext torat"
                        $string2 = /\/persist_cortana\.py/ nocase ascii wide
                        $string3 = /\/persist_people\.py/ nocase ascii wide
                        $string4 = /\/persit_linux\.go/
                        $string5 = /\/persit_windows\.go/ nocase ascii wide
                        $string6 = /\/ToRat\.git/ nocase ascii wide
                        $string7 = /\/tor\-static\-windows\-amd64\.zip/ nocase ascii wide
                        $string8 = /\\persist_cortana\.py/ nocase ascii wide
                        $string9 = /\\persist_people\.py/ nocase ascii wide
                        $string10 = /\\persit_linux\.go/ nocase ascii wide
                        $string11 = /\\persit_windows\.go/ nocase ascii wide
                        $string12 = /\\ToRat\\cmd\\/ nocase ascii wide
                        $string13 = /\\ToRat\\keygen\\/ nocase ascii wide
                        $string14 = /\\ToRat\\torat_client\\/ nocase ascii wide
                        $string15 = /\\ToRat\\torat_server\\/ nocase ascii wide
                        $string16 = /\\ToRat\-master\.zip/ nocase ascii wide
                        $string17 = /\\tor\-static\-windows\-amd64\.zip/ nocase ascii wide
                        $string18 = /docker\sbuild\s\.\s\-t\storat/ nocase ascii wide
                        $string19 = "docker run -it torat" nocase ascii wide
                        $string20 = /localhost\:8000\/.{0,1000}\/hardware/ nocase ascii wide
                        $string21 = /localhost\:8000\/.{0,1000}\/netscan/ nocase ascii wide
                        $string22 = /localhost\:8000\/.{0,1000}\/osinfo/ nocase ascii wide
                        $string23 = /localhost\:8000\/.{0,1000}\/speedtest/ nocase ascii wide
                        $string24 = "lu4p/ToRat" nocase ascii wide
                        $string25 = "server/ToRat_server" nocase ascii wide
                        $string26 = "torEd25519" nocase ascii wide

    condition:
        any of them
}