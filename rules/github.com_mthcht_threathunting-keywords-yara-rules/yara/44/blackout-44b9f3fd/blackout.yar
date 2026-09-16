rule Blackout
{
    meta:
        description = "Detection patterns for the tool 'Blackout' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Blackout"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sBlackout\.cpp/ nocase ascii wide
                        $string2 = /\sBlackout\.sln/ nocase ascii wide
                        $string3 = /\sBlackout\.sys/ nocase ascii wide
                        $string4 = /\/Blackout\.cpp/ nocase ascii wide
                        $string5 = /\/Blackout\.exe/ nocase ascii wide
                        $string6 = /\/Blackout\.git/ nocase ascii wide
                        $string7 = /\/Blackout\.sln/ nocase ascii wide
                        $string8 = /\/Blackout\.sys/ nocase ascii wide
                        $string9 = /\\Blackout\.cpp/ nocase ascii wide
                        $string10 = /\\Blackout\.exe/ nocase ascii wide
                        $string11 = /\\Blackout\.sln/ nocase ascii wide
                        $string12 = /\\Blackout\.sys/ nocase ascii wide
                        $string13 = /\\Blackout\.vcxproj/ nocase ascii wide
                        $string14 = /Blackout\.exe\s/ nocase ascii wide
                        $string15 = "ZeroMemoryEx/Blackout" nocase ascii wide

    condition:
        any of them
}