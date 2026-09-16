rule EventViewer_UACBypass
{
    meta:
        description = "Detection patterns for the tool 'EventViewer-UACBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventViewer-UACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " EventViewer-UACBypass" nocase ascii wide
                        $string2 = "/EventViewer-UACBypass" nocase ascii wide
                        $string3 = /\\EventViewer\-UACBypass/ nocase ascii wide
                        $string4 = /\\Windows\\Tasks\\p4yl0ad/ nocase ascii wide
                        $string5 = /EventViewerRCE\.ps1/ nocase ascii wide
                        $string6 = /Invoke\-EventViewer\s.{0,1000}\.exe/ nocase ascii wide
                        $string7 = /Invoke\-EventViewer\.ps1/ nocase ascii wide
                        $string8 = "OgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXABFAHYAZQBuAHQAVgBpAGUAdwBlAHIAUgBDAEUALgBwAHMAMQA=" nocase ascii wide

    condition:
        any of them
}