rule SharpBlackout
{
    meta:
        description = "Detection patterns for the tool 'SharpBlackout' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBlackout"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpBlackout\.git/ nocase ascii wide
                        $string2 = "07DFC5AA-5B1F-4CCC-A3D3-816ECCBB6CB6" nocase ascii wide
                        $string3 = "dmcxblue/SharpBlackout" nocase ascii wide
                        $string4 = /SharpBlackout.{0,1000}\s\-p\s/ nocase ascii wide
                        $string5 = /SharpBlackOut\.csproj/ nocase ascii wide
                        $string6 = /SharpBlackout\.exe/ nocase ascii wide
                        $string7 = /SharpBlackOut\.pdb/ nocase ascii wide
                        $string8 = /SharpBlackOut\.sln/ nocase ascii wide
                        $string9 = "SharpBlackout-main" nocase ascii wide
                        $string10 = /Terminating\sWindows\sDefender\?/ nocase ascii wide

    condition:
        any of them
}