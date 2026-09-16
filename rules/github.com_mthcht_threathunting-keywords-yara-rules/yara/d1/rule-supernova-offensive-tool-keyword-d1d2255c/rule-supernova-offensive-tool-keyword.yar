rule rule_Supernova_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Supernova' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supernova"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Supernova_offensive_tool_keyword = /\.bin\s\-enc\src4\s\-lang\sc\s\-k\s3\s\-o\s.{0,1000}\.bin/ nocase ascii wide
                        $string2_Supernova_offensive_tool_keyword = /\.bin\s\-enc\src4\s\-lang\scsharp\s\-k\s9/ nocase ascii wide
                        $string3_Supernova_offensive_tool_keyword = /\.bin\s\-enc\srot\s\-lang\scsharp\s\-k\s2\s\-d/ nocase ascii wide
                        $string4_Supernova_offensive_tool_keyword = /\.bin\s\-enc\srot\s\-lang\srust\s\-k\s7/ nocase ascii wide
                        $string5_Supernova_offensive_tool_keyword = /\.bin\s\-enc\sxor\s\-lang\scsharp\s\-k\s2\s\-v\snickvourd/ nocase ascii wide
                        $string6_Supernova_offensive_tool_keyword = /\.bin\s\-enc\sxor\s\-lang\snim\s\-k\s4/ nocase ascii wide
                        $string7_Supernova_offensive_tool_keyword = /\.exe\s.{0,1000}\.bin\s\-enc\saes\s\-lang\scsharp/ nocase ascii wide
                        $string8_Supernova_offensive_tool_keyword = /\/Supernova\.exe/ nocase ascii wide
                        $string9_Supernova_offensive_tool_keyword = /\/Supernova\.git/ nocase ascii wide
                        $string10_Supernova_offensive_tool_keyword = /\[\+\]\sGenerated\sXOR\skey\:\s/ nocase ascii wide
                        $string11_Supernova_offensive_tool_keyword = /\[\+\]\sSave\sencrypted\sshellcode\sto\s/ nocase ascii wide
                        $string12_Supernova_offensive_tool_keyword = /\[\+\]\sThe\sencrypted\spayload\swith\s/ nocase ascii wide
                        $string13_Supernova_offensive_tool_keyword = /\\Supernova\.exe/ nocase ascii wide
                        $string14_Supernova_offensive_tool_keyword = /build\sSupernova\.go/ nocase ascii wide
                        $string15_Supernova_offensive_tool_keyword = "nickvourd/Supernova" nocase ascii wide
                        $string16_Supernova_offensive_tool_keyword = /Supernova\.exe\s\-/ nocase ascii wide
                        $string17_Supernova_offensive_tool_keyword = /Supernova\-main\.zip/ nocase ascii wide

    condition:
        any of them
}