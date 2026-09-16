rule rule_AoratosWin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AoratosWin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AoratosWin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AoratosWin_offensive_tool_keyword = "/AoratosWin/" nocase ascii wide
                        $string2_AoratosWin_offensive_tool_keyword = /\\AoratosWin/ nocase ascii wide
                        $string3_AoratosWin_offensive_tool_keyword = /AoratosWin.{0,1000}\.zip/ nocase ascii wide
                        $string4_AoratosWin_offensive_tool_keyword = /AoratosWin\.csproj/ nocase ascii wide
                        $string5_AoratosWin_offensive_tool_keyword = /AoratosWin\.exe/ nocase ascii wide
                        $string6_AoratosWin_offensive_tool_keyword = /AoratosWin\.git/ nocase ascii wide
                        $string7_AoratosWin_offensive_tool_keyword = /AoratosWin\.sln/ nocase ascii wide
                        $string8_AoratosWin_offensive_tool_keyword = /AoratosWin_.{0,1000}\.zip/ nocase ascii wide
                        $string9_AoratosWin_offensive_tool_keyword = "E731C71B-4D1B-4BE7-AA4D-EDA52AF7F256" nocase ascii wide
                        $string10_AoratosWin_offensive_tool_keyword = "PinoyWH1Z/AoratosWin" nocase ascii wide
                        $string11_AoratosWin_offensive_tool_keyword = "removeRegTrace" nocase ascii wide
                        $string12_AoratosWin_offensive_tool_keyword = "whoami /user" nocase ascii wide

    condition:
        any of them
}