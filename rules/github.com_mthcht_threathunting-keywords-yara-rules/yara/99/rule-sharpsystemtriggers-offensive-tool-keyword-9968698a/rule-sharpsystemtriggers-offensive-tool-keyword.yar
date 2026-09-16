rule rule_SharpSystemTriggers_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSystemTriggers' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSystemTriggers"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSystemTriggers_offensive_tool_keyword = "/SharpSpoolTrigger" nocase ascii wide
                        $string2_SharpSystemTriggers_offensive_tool_keyword = "/SharpSystemTriggers" nocase ascii wide
                        $string3_SharpSystemTriggers_offensive_tool_keyword = /Midl2Bytes\.exe/ nocase ascii wide
                        $string4_SharpSystemTriggers_offensive_tool_keyword = /SharpDcomTrigger\.exe/ nocase ascii wide
                        $string5_SharpSystemTriggers_offensive_tool_keyword = /SharpEfsTriggeEfs\.exe/ nocase ascii wide
                        $string6_SharpSystemTriggers_offensive_tool_keyword = /SharpSpoolTrigger\.exe/ nocase ascii wide
                        $string7_SharpSystemTriggers_offensive_tool_keyword = /SharpSystemTriggers\.git/ nocase ascii wide
                        $string8_SharpSystemTriggers_offensive_tool_keyword = /SharpSystemTriggers\.sln/ nocase ascii wide
                        $string9_SharpSystemTriggers_offensive_tool_keyword = "SharpSystemTriggers-main" nocase ascii wide

    condition:
        any of them
}