rule Alcatraz
{
    meta:
        description = "Detection patterns for the tool 'Alcatraz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alcatraz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAlcatraz\.exe/ nocase ascii wide
                        $string2 = /\/Alcatraz\.exe/ nocase ascii wide
                        $string3 = /\/Alcatraz\.git/ nocase ascii wide
                        $string4 = /\/Alcatraz\/files\/.{0,1000}\/Alcatraz\.zip/ nocase ascii wide
                        $string5 = "/Alcatraz/x64" nocase ascii wide
                        $string6 = "/Alcatraz-gui" nocase ascii wide
                        $string7 = /\/obfuscator\/obfuscator\./ nocase ascii wide
                        $string8 = /\\Alcatraz\.exe/ nocase ascii wide
                        $string9 = /Alcatraz\.sln/ nocase ascii wide
                        $string10 = /Alcatraz\.vcxproj/ nocase ascii wide
                        $string11 = "Alcatraz/obfuscator" nocase ascii wide
                        $string12 = /Alcatraz\-master\.zip/ nocase ascii wide
                        $string13 = /obfuscator.{0,1000}antidisassembly\./ nocase ascii wide
                        $string14 = /obfuscator\.cpp/ nocase ascii wide
                        $string15 = "weak1337/Alcatraz" nocase ascii wide

    condition:
        any of them
}