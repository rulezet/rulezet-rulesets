rule rule_DoHC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DoHC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoHC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DoHC2_offensive_tool_keyword = /\/BeaconChannel\.cs/ nocase ascii wide
                        $string2_DoHC2_offensive_tool_keyword = /\/DoHC2\.cs/ nocase ascii wide
                        $string3_DoHC2_offensive_tool_keyword = /\/DoHC2\.git/ nocase ascii wide
                        $string4_DoHC2_offensive_tool_keyword = "/DoHC2/" nocase ascii wide
                        $string5_DoHC2_offensive_tool_keyword = "/ExternalC2/" nocase ascii wide
                        $string6_DoHC2_offensive_tool_keyword = /\/WebC2\.cs/
                        $string7_DoHC2_offensive_tool_keyword = /\/WebSocketC2\.cs/ nocase ascii wide
                        $string8_DoHC2_offensive_tool_keyword = /\\BeaconChannel\.cs/ nocase ascii wide
                        $string9_DoHC2_offensive_tool_keyword = /\\BeaconConnector\.cs/ nocase ascii wide
                        $string10_DoHC2_offensive_tool_keyword = /\\DoHC2\.cs/ nocase ascii wide
                        $string11_DoHC2_offensive_tool_keyword = /\\ExternalC2\\/ nocase ascii wide
                        $string12_DoHC2_offensive_tool_keyword = /0\.0\.0\.0\:2222/ nocase ascii wide
                        $string13_DoHC2_offensive_tool_keyword = /127\.0\.0\.1\:2222/ nocase ascii wide
                        $string14_DoHC2_offensive_tool_keyword = /C2WebSocketHandler\./ nocase ascii wide
                        $string15_DoHC2_offensive_tool_keyword = "Cobalt Strike external C2" nocase ascii wide
                        $string16_DoHC2_offensive_tool_keyword = /DoHC2.{0,1000}BeaconConnector/ nocase ascii wide
                        $string17_DoHC2_offensive_tool_keyword = /DoHC2\.exe/ nocase ascii wide
                        $string18_DoHC2_offensive_tool_keyword = /DoHC2\.py/ nocase ascii wide
                        $string19_DoHC2_offensive_tool_keyword = /DoHC2Runner\./ nocase ascii wide
                        $string20_DoHC2_offensive_tool_keyword = /DoHC2Runner\.exe/ nocase ascii wide
                        $string21_DoHC2_offensive_tool_keyword = /DoHC2Runner\.pdb/ nocase ascii wide
                        $string22_DoHC2_offensive_tool_keyword = /DoHChannel\.cs/ nocase ascii wide
                        $string23_DoHC2_offensive_tool_keyword = /external_c2\.cna/ nocase ascii wide
                        $string24_DoHC2_offensive_tool_keyword = /ExternalC2\./ nocase ascii wide
                        $string25_DoHC2_offensive_tool_keyword = /ExternalC2\.dll/ nocase ascii wide
                        $string26_DoHC2_offensive_tool_keyword = "externalc2_start" nocase ascii wide
                        $string27_DoHC2_offensive_tool_keyword = "ExternalC2Core" nocase ascii wide
                        $string28_DoHC2_offensive_tool_keyword = "ExternalC2-master" nocase ascii wide
                        $string29_DoHC2_offensive_tool_keyword = "ExternalC2Tests" nocase ascii wide
                        $string30_DoHC2_offensive_tool_keyword = "ExternalC2Web" nocase ascii wide
                        $string31_DoHC2_offensive_tool_keyword = "go-external-c2" nocase ascii wide
                        $string32_DoHC2_offensive_tool_keyword = "package externc2" nocase ascii wide
                        $string33_DoHC2_offensive_tool_keyword = "SpiderLabs/DoHC2" nocase ascii wide
                        $string34_DoHC2_offensive_tool_keyword = "X-C2-Beacon" nocase ascii wide

    condition:
        any of them
}