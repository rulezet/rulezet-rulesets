rule rule_ChromeStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ChromeStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChromeStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ChromeStealer_offensive_tool_keyword = /\/ChromeStealer\.git/ nocase ascii wide
                        $string2_ChromeStealer_offensive_tool_keyword = /\\ChromeStealer\.cpp/ nocase ascii wide
                        $string3_ChromeStealer_offensive_tool_keyword = /\\ChromeStealer\.sln/ nocase ascii wide
                        $string4_ChromeStealer_offensive_tool_keyword = /\\ChromeStealer\-main/ nocase ascii wide
                        $string5_ChromeStealer_offensive_tool_keyword = "1aebc75f4a66ba1711c288235dad6ac01c59e8801e8a1c2151cbb7dfd4c2c098" nocase ascii wide
                        $string6_ChromeStealer_offensive_tool_keyword = "64d2173109cdc67df6e9e15a275b4ed0b5488397c290b996ffd3ed445f361b79" nocase ascii wide
                        $string7_ChromeStealer_offensive_tool_keyword = "BernKing/ChromeStealer" nocase ascii wide
                        $string8_ChromeStealer_offensive_tool_keyword = "c7c8b6fb-4e59-494e-aeeb-40cf342a7e88" nocase ascii wide
                        $string9_ChromeStealer_offensive_tool_keyword = /ChromeStealer\.exe/ nocase ascii wide

    condition:
        any of them
}