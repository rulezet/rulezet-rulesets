rule rule_NetLoader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetLoader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetLoader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NetLoader_offensive_tool_keyword = /\.exe\s\s\-\-b64\s\-\-path\s.{0,1000}\s\-\-args\s/ nocase ascii wide
                        $string2_NetLoader_offensive_tool_keyword = /\/NetLoader\.git/ nocase ascii wide
                        $string3_NetLoader_offensive_tool_keyword = /\\NetLoader\.exe/ nocase ascii wide
                        $string4_NetLoader_offensive_tool_keyword = /csc\.exe\s\/t\:exe\s\/out\:RandomName\.exe\sProgram\.cs/ nocase ascii wide
                        $string5_NetLoader_offensive_tool_keyword = "d2hvYW1p" nocase ascii wide
                        $string6_NetLoader_offensive_tool_keyword = "Flangvik/NetLoader" nocase ascii wide
                        $string7_NetLoader_offensive_tool_keyword = /LOLBins\/NetLoader\.xml/ nocase ascii wide
                        $string8_NetLoader_offensive_tool_keyword = /MSBuild\.exe\sNetLoader\.xml/ nocase ascii wide
                        $string9_NetLoader_offensive_tool_keyword = /NetLoader\.exe\s\-\-path\s.{0,1000}\.exe\s/ nocase ascii wide
                        $string10_NetLoader_offensive_tool_keyword = "NetLoader-master" nocase ascii wide
                        $string11_NetLoader_offensive_tool_keyword = "U2VhdGJlbHQuZXhl" nocase ascii wide

    condition:
        any of them
}