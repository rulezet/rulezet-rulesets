rule Nsight_RMM
{
    meta:
        description = "Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nsight RMM"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\supload.{0,1000}\.systemmonitor\.eu\.com.{0,1000}\/command\/agentprocessor/ nocase ascii wide
                        $string2 = /\\Advanced\sMonitoring\sAgent\\debug\.log/ nocase ascii wide
                        $string3 = /\\Advanced\sMonitoring\sAgent\\staging/ nocase ascii wide
                        $string4 = /\\Advanced\sMonitoring\sAgent\\task_start\.js/ nocase ascii wide
                        $string5 = /\\Advanced\sMonitoring\sAgent\\unzip\.exe/ nocase ascii wide
                        $string6 = /\\Advanced\sMonitoring\sAgent\\winagent\.exe/ nocase ascii wide
                        $string7 = /\\Program\sFiles\s\(x86\)\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
                        $string8 = /\\Program\sFiles\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
                        $string9 = /\\Start\sMenu\\Programs\\Advanced\sMonitoring\sAgent\.lnk/ nocase ascii wide
                        $string10 = /Advanced\sMonitoring\sAgent\sHTTP\sRetriever\s1\.1/ nocase ascii wide

    condition:
        any of them
}