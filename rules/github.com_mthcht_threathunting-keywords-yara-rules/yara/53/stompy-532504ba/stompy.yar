rule Stompy
{
    meta:
        description = "Detection patterns for the tool 'Stompy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stompy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sStompy\.ps1/ nocase ascii wide
                        $string2 = /\sStomPY\.py\s/ nocase ascii wide
                        $string3 = /\.\/GoStompy\s/
                        $string4 = /\.exe.{0,1000}\s\-path\s.{0,1000}\s\-newTimestamp\s.{0,1000}\s\-username\s.{0,1000}\s\-password\s/ nocase ascii wide
                        $string5 = /\/GoStompy\.go/ nocase ascii wide
                        $string6 = /\/Stompy\.git/ nocase ascii wide
                        $string7 = /\/Stompy\.ps1/ nocase ascii wide
                        $string8 = /\/StomPY\.py/ nocase ascii wide
                        $string9 = /\\GoStompy\.go/ nocase ascii wide
                        $string10 = /\\Stompy\.ps1/ nocase ascii wide
                        $string11 = /\\StomPY\.py/ nocase ascii wide
                        $string12 = /\\Stompy\-main\\/ nocase ascii wide
                        $string13 = "784F8029-4D72-4363-9638-5A8D11545494" nocase ascii wide
                        $string14 = /build\sGoStompy\.go/ nocase ascii wide
                        $string15 = "Invoke-Stompy" nocase ascii wide
                        $string16 = /StompySharps\.csproj/ nocase ascii wide
                        $string17 = /StompySharps\.exe/ nocase ascii wide
                        $string18 = /StompySharps\.sln/ nocase ascii wide
                        $string19 = "ZephrFish/Stompy" nocase ascii wide

    condition:
        any of them
}