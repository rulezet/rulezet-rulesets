rule rule_EventViewer_UACBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EventViewer-UACBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventViewer-UACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EventViewer_UACBypass_offensive_tool_keyword = " EventViewer-UACBypass" nocase ascii wide
                        $string2_EventViewer_UACBypass_offensive_tool_keyword = "/EventViewer-UACBypass" nocase ascii wide
                        $string3_EventViewer_UACBypass_offensive_tool_keyword = /\\EventViewer\-UACBypass/ nocase ascii wide
                        $string4_EventViewer_UACBypass_offensive_tool_keyword = /\\Windows\\Tasks\\p4yl0ad/ nocase ascii wide
                        $string5_EventViewer_UACBypass_offensive_tool_keyword = /EventViewerRCE\.ps1/ nocase ascii wide
                        $string6_EventViewer_UACBypass_offensive_tool_keyword = /Invoke\-EventViewer\s.{0,1000}\.exe/ nocase ascii wide
                        $string7_EventViewer_UACBypass_offensive_tool_keyword = /Invoke\-EventViewer\.ps1/ nocase ascii wide
                        $string8_EventViewer_UACBypass_offensive_tool_keyword = "OgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXABFAHYAZQBuAHQAVgBpAGUAdwBlAHIAUgBDAEUALgBwAHMAMQA=" nocase ascii wide

    condition:
        any of them
}