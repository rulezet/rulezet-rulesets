rule rule_hades_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hades' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hades"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hades_offensive_tool_keyword = /\.exe.{0,1000}\s\-f\s.{0,1000}\.bin\s\-t\squeueuserapc/ nocase ascii wide
                        $string2_hades_offensive_tool_keyword = /\.exe.{0,1000}\s\-t\squeueuserapc/ nocase ascii wide
                        $string3_hades_offensive_tool_keyword = /\.exe.{0,1000}\s\-t\sremotethread/ nocase ascii wide
                        $string4_hades_offensive_tool_keyword = /\.exe.{0,1000}\s\-t\sselfthread/ nocase ascii wide
                        $string5_hades_offensive_tool_keyword = /\.exe.{0,1000}\s\-\-technique\squeueuserapc/ nocase ascii wide
                        $string6_hades_offensive_tool_keyword = /\.exe.{0,1000}\s\-\-technique\sremotethread/ nocase ascii wide
                        $string7_hades_offensive_tool_keyword = /\.exe.{0,1000}\s\-\-technique\sselfthread/ nocase ascii wide
                        $string8_hades_offensive_tool_keyword = "/cmd/hades/" nocase ascii wide
                        $string9_hades_offensive_tool_keyword = /\/hades\.git/ nocase ascii wide
                        $string10_hades_offensive_tool_keyword = /\/hades\-main\.zip/ nocase ascii wide
                        $string11_hades_offensive_tool_keyword = /\\hades\.exe/ nocase ascii wide
                        $string12_hades_offensive_tool_keyword = /\\hades\-main\.zip/ nocase ascii wide
                        $string13_hades_offensive_tool_keyword = "f1zm0/hades" nocase ascii wide
                        $string14_hades_offensive_tool_keyword = /hades_directsys\.exe/ nocase ascii wide

    condition:
        any of them
}