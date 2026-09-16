rule AoratosWin
{
    meta:
        description = "Detection patterns for the tool 'AoratosWin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AoratosWin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/AoratosWin/" nocase ascii wide
                        $string2 = /\\AoratosWin/ nocase ascii wide
                        $string3 = /AoratosWin.{0,1000}\.zip/ nocase ascii wide
                        $string4 = /AoratosWin\.csproj/ nocase ascii wide
                        $string5 = /AoratosWin\.exe/ nocase ascii wide
                        $string6 = /AoratosWin\.git/ nocase ascii wide
                        $string7 = /AoratosWin\.sln/ nocase ascii wide
                        $string8 = /AoratosWin_.{0,1000}\.zip/ nocase ascii wide
                        $string9 = "E731C71B-4D1B-4BE7-AA4D-EDA52AF7F256" nocase ascii wide
                        $string10 = "PinoyWH1Z/AoratosWin" nocase ascii wide
                        $string11 = "removeRegTrace" nocase ascii wide
                        $string12 = "whoami /user" nocase ascii wide

    condition:
        any of them
}