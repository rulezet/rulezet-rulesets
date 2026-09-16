rule rule_ETWEventSubscription_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ETWEventSubscription' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ETWEventSubscription"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ETWEventSubscription_offensive_tool_keyword = /DoEvil\(\)/ nocase ascii wide
                        $string2_ETWEventSubscription_offensive_tool_keyword = /ETWEventSubscription.{0,1000}Program\.cs/ nocase ascii wide
                        $string3_ETWEventSubscription_offensive_tool_keyword = /ETWEventSubscription\.exe.{0,1000}\s\-ProcStart\s/ nocase ascii wide
                        $string4_ETWEventSubscription_offensive_tool_keyword = /ETWEventSubscription\.exe.{0,1000}\s\-UserLogon/ nocase ascii wide
                        $string5_ETWEventSubscription_offensive_tool_keyword = /OffensiveCSharp.{0,1000}ETWEventSubscription/ nocase ascii wide

    condition:
        any of them
}