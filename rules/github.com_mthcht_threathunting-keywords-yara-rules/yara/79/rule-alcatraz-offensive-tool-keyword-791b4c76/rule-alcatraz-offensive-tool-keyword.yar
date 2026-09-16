rule rule_Alcatraz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Alcatraz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alcatraz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Alcatraz_offensive_tool_keyword = /\sAlcatraz\.exe/ nocase ascii wide
                        $string2_Alcatraz_offensive_tool_keyword = /\/Alcatraz\.exe/ nocase ascii wide
                        $string3_Alcatraz_offensive_tool_keyword = /\/Alcatraz\.git/ nocase ascii wide
                        $string4_Alcatraz_offensive_tool_keyword = /\/Alcatraz\/files\/.{0,1000}\/Alcatraz\.zip/ nocase ascii wide
                        $string5_Alcatraz_offensive_tool_keyword = "/Alcatraz/x64" nocase ascii wide
                        $string6_Alcatraz_offensive_tool_keyword = "/Alcatraz-gui" nocase ascii wide
                        $string7_Alcatraz_offensive_tool_keyword = /\/obfuscator\/obfuscator\./ nocase ascii wide
                        $string8_Alcatraz_offensive_tool_keyword = /\\Alcatraz\.exe/ nocase ascii wide
                        $string9_Alcatraz_offensive_tool_keyword = /Alcatraz\.sln/ nocase ascii wide
                        $string10_Alcatraz_offensive_tool_keyword = /Alcatraz\.vcxproj/ nocase ascii wide
                        $string11_Alcatraz_offensive_tool_keyword = "Alcatraz/obfuscator" nocase ascii wide
                        $string12_Alcatraz_offensive_tool_keyword = /Alcatraz\-master\.zip/ nocase ascii wide
                        $string13_Alcatraz_offensive_tool_keyword = /obfuscator.{0,1000}antidisassembly\./ nocase ascii wide
                        $string14_Alcatraz_offensive_tool_keyword = /obfuscator\.cpp/ nocase ascii wide
                        $string15_Alcatraz_offensive_tool_keyword = "weak1337/Alcatraz" nocase ascii wide

    condition:
        any of them
}