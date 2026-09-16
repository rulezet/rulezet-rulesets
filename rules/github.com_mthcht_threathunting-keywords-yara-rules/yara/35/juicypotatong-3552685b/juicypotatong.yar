rule JuicyPotatoNG
{
    meta:
        description = "Detection patterns for the tool 'JuicyPotatoNG' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JuicyPotatoNG"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " JuicyPotatoNG" nocase ascii wide
                        $string2 = /\.exe\s\-l\s.{0,1000}\s\-c\s\{B91D5831\-B1BD\-4608\-8198\-D72E155020F7\}/ nocase ascii wide
                        $string3 = /\.exe\s\-l\s.{0,1000}\s\-c\s\{F7FD3FD6\-9994\-452D\-8DA7\-9A8FD87AEEF4\}\s\-a/ nocase ascii wide
                        $string4 = /\/JuicyPotatoNG\.git/ nocase ascii wide
                        $string5 = /\[\-\]\sExploit\sfailed\!\s/ nocase ascii wide
                        $string6 = /\[\+\]\sExploit\ssuccessful\!\s/ nocase ascii wide
                        $string7 = /\\JuicyPotatoNG/ nocase ascii wide
                        $string8 = /\]\sBruteforcing\s\%d\sCLSIDs/ nocase ascii wide
                        $string9 = "261f880e-4bee-428d-9f64-c29292002c19" nocase ascii wide
                        $string10 = "antonioCoco/JuicyPotatoNG" nocase ascii wide
                        $string11 = /BruteforceCLSIDs\./ nocase ascii wide
                        $string12 = "c5af796b44a3d3d09e184ef622ad002b8298696c2de139392fd35898f5073527" nocase ascii wide
                        $string13 = "C73A4893-A5D1-44C8-900C-7B8850BBD2EC" nocase ascii wide
                        $string14 = /JuicyPotatoNG\.cpp/ nocase ascii wide
                        $string15 = /JuicyPotatoNG\.exe/ nocase ascii wide
                        $string16 = /JuicyPotatoNG\.sln/ nocase ascii wide
                        $string17 = /JuicyPotatoNG\.txt/ nocase ascii wide
                        $string18 = /JuicyPotatoNG\.zip/ nocase ascii wide
                        $string19 = "JuicyPotatoNG-main" nocase ascii wide
                        $string20 = /PotatoTrigger\.cpp/ nocase ascii wide

    condition:
        any of them
}