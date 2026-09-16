rule hades
{
    meta:
        description = "Detection patterns for the tool 'hades' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hades"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe.{0,1000}\s\-f\s.{0,1000}\.bin\s\-t\squeueuserapc/ nocase ascii wide
                        $string2 = /\.exe.{0,1000}\s\-t\squeueuserapc/ nocase ascii wide
                        $string3 = /\.exe.{0,1000}\s\-t\sremotethread/ nocase ascii wide
                        $string4 = /\.exe.{0,1000}\s\-t\sselfthread/ nocase ascii wide
                        $string5 = /\.exe.{0,1000}\s\-\-technique\squeueuserapc/ nocase ascii wide
                        $string6 = /\.exe.{0,1000}\s\-\-technique\sremotethread/ nocase ascii wide
                        $string7 = /\.exe.{0,1000}\s\-\-technique\sselfthread/ nocase ascii wide
                        $string8 = "/cmd/hades/" nocase ascii wide
                        $string9 = /\/hades\.git/ nocase ascii wide
                        $string10 = /\/hades\-main\.zip/ nocase ascii wide
                        $string11 = /\\hades\.exe/ nocase ascii wide
                        $string12 = /\\hades\-main\.zip/ nocase ascii wide
                        $string13 = "f1zm0/hades" nocase ascii wide
                        $string14 = /hades_directsys\.exe/ nocase ascii wide

    condition:
        any of them
}