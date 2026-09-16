rule rule_Stompy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Stompy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stompy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Stompy_offensive_tool_keyword = /\sStompy\.ps1/ nocase ascii wide
                        $string2_Stompy_offensive_tool_keyword = /\sStomPY\.py\s/ nocase ascii wide
                        $string3_Stompy_offensive_tool_keyword = /\.\/GoStompy\s/
                        $string4_Stompy_offensive_tool_keyword = /\.exe.{0,1000}\s\-path\s.{0,1000}\s\-newTimestamp\s.{0,1000}\s\-username\s.{0,1000}\s\-password\s/ nocase ascii wide
                        $string5_Stompy_offensive_tool_keyword = /\/GoStompy\.go/ nocase ascii wide
                        $string6_Stompy_offensive_tool_keyword = /\/Stompy\.git/ nocase ascii wide
                        $string7_Stompy_offensive_tool_keyword = /\/Stompy\.ps1/ nocase ascii wide
                        $string8_Stompy_offensive_tool_keyword = /\/StomPY\.py/ nocase ascii wide
                        $string9_Stompy_offensive_tool_keyword = /\\GoStompy\.go/ nocase ascii wide
                        $string10_Stompy_offensive_tool_keyword = /\\Stompy\.ps1/ nocase ascii wide
                        $string11_Stompy_offensive_tool_keyword = /\\StomPY\.py/ nocase ascii wide
                        $string12_Stompy_offensive_tool_keyword = /\\Stompy\-main\\/ nocase ascii wide
                        $string13_Stompy_offensive_tool_keyword = "784F8029-4D72-4363-9638-5A8D11545494" nocase ascii wide
                        $string14_Stompy_offensive_tool_keyword = /build\sGoStompy\.go/ nocase ascii wide
                        $string15_Stompy_offensive_tool_keyword = "Invoke-Stompy" nocase ascii wide
                        $string16_Stompy_offensive_tool_keyword = /StompySharps\.csproj/ nocase ascii wide
                        $string17_Stompy_offensive_tool_keyword = /StompySharps\.exe/ nocase ascii wide
                        $string18_Stompy_offensive_tool_keyword = /StompySharps\.sln/ nocase ascii wide
                        $string19_Stompy_offensive_tool_keyword = "ZephrFish/Stompy" nocase ascii wide

    condition:
        any of them
}