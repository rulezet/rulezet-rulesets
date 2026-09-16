rule rule_DebugAmsi_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DebugAmsi' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DebugAmsi"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DebugAmsi_offensive_tool_keyword = /\/DebugAmsi\.git/ nocase ascii wide
                        $string2_DebugAmsi_offensive_tool_keyword = "375D8508-F60D-4E24-9DF6-1E591D2FA474" nocase ascii wide
                        $string3_DebugAmsi_offensive_tool_keyword = /DebugAmsi\.exe/ nocase ascii wide
                        $string4_DebugAmsi_offensive_tool_keyword = /DebugAmsi\.sln/ nocase ascii wide
                        $string5_DebugAmsi_offensive_tool_keyword = /DebugAmsi\.vcxproj/ nocase ascii wide
                        $string6_DebugAmsi_offensive_tool_keyword = "DebugAmsi-main" nocase ascii wide
                        $string7_DebugAmsi_offensive_tool_keyword = /DebugAmsix64\.exe/ nocase ascii wide
                        $string8_DebugAmsi_offensive_tool_keyword = /DebugAmsix86\.exe/ nocase ascii wide
                        $string9_DebugAmsi_offensive_tool_keyword = "MzHmO/DebugAmsi" nocase ascii wide

    condition:
        any of them
}