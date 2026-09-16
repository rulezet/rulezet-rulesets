rule rule_Offensive_Netsh_Helper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Netsh-Helper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Netsh-Helper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Offensive_Netsh_Helper_offensive_tool_keyword = /\/Offensive\-Netsh\-Helper\.git/ nocase ascii wide
                        $string2_Offensive_Netsh_Helper_offensive_tool_keyword = /\\netshlep\.cpp/ nocase ascii wide
                        $string3_Offensive_Netsh_Helper_offensive_tool_keyword = /\\Offensive\-Netsh\-Helper\\/ nocase ascii wide
                        $string4_Offensive_Netsh_Helper_offensive_tool_keyword = /\\Offensive\-Netsh\-Helper\-master/ nocase ascii wide
                        $string5_Offensive_Netsh_Helper_offensive_tool_keyword = "486d59732d2c346aa2cbaffff0d290b0e5fc0a967e0878240fd29df65525dfc8" nocase ascii wide
                        $string6_Offensive_Netsh_Helper_offensive_tool_keyword = "cwB0AGEAcgB0ACAAYwBhAGwAYwA=" nocase ascii wide
                        $string7_Offensive_Netsh_Helper_offensive_tool_keyword = /netsh\sadd\shelper\snetshBad\.DLL/ nocase ascii wide
                        $string8_Offensive_Netsh_Helper_offensive_tool_keyword = "rtcrowley/Offensive-Netsh-Helper" nocase ascii wide

    condition:
        any of them
}