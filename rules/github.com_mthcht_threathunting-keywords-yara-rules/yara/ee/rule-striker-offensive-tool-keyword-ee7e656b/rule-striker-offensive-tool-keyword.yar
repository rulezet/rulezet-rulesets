rule rule_Striker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Striker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Striker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Striker_offensive_tool_keyword = /\.\/redirector\.py\s/
                        $string2_Striker_offensive_tool_keyword = /\.striker\.local/ nocase ascii wide
                        $string3_Striker_offensive_tool_keyword = "/agent/C/src/" nocase ascii wide
                        $string4_Striker_offensive_tool_keyword = /\/redirector\/redirector\.py/ nocase ascii wide
                        $string5_Striker_offensive_tool_keyword = "/sites-available/striker" nocase ascii wide
                        $string6_Striker_offensive_tool_keyword = "/sites-enabled/striker" nocase ascii wide
                        $string7_Striker_offensive_tool_keyword = /\/striker\.c/ nocase ascii wide
                        $string8_Striker_offensive_tool_keyword = /\/Striker\.git/ nocase ascii wide
                        $string9_Striker_offensive_tool_keyword = /\/striker\.local/ nocase ascii wide
                        $string10_Striker_offensive_tool_keyword = "4g3nt47/Striker" nocase ascii wide
                        $string11_Striker_offensive_tool_keyword = "bin/striker" nocase ascii wide
                        $string12_Striker_offensive_tool_keyword = /c2\.striker\./ nocase ascii wide
                        $string13_Striker_offensive_tool_keyword = /localhost\:3000.{0,1000}striker/ nocase ascii wide
                        $string14_Striker_offensive_tool_keyword = /nginx\/striker\.log/ nocase ascii wide
                        $string15_Striker_offensive_tool_keyword = /s0md3v.{0,1000}Striker/ nocase ascii wide
                        $string16_Striker_offensive_tool_keyword = /src\/obfuscator\.c/ nocase ascii wide
                        $string17_Striker_offensive_tool_keyword = "VITE_STRIKER_API" nocase ascii wide

    condition:
        any of them
}