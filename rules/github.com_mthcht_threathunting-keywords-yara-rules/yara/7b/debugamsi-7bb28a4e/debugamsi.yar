rule DebugAmsi
{
    meta:
        description = "Detection patterns for the tool 'DebugAmsi' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DebugAmsi"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DebugAmsi\.git/ nocase ascii wide
                        $string2 = "375D8508-F60D-4E24-9DF6-1E591D2FA474" nocase ascii wide
                        $string3 = /DebugAmsi\.exe/ nocase ascii wide
                        $string4 = /DebugAmsi\.sln/ nocase ascii wide
                        $string5 = /DebugAmsi\.vcxproj/ nocase ascii wide
                        $string6 = "DebugAmsi-main" nocase ascii wide
                        $string7 = /DebugAmsix64\.exe/ nocase ascii wide
                        $string8 = /DebugAmsix86\.exe/ nocase ascii wide
                        $string9 = "MzHmO/DebugAmsi" nocase ascii wide

    condition:
        any of them
}