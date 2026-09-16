rule rule_Nsight_RMM_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nsight RMM"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Nsight_RMM_greyware_tool_keyword = /\supload.{0,1000}\.systemmonitor\.eu\.com.{0,1000}\/command\/agentprocessor/ nocase ascii wide
                        $string2_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\debug\.log/ nocase ascii wide
                        $string3_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\staging/ nocase ascii wide
                        $string4_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\task_start\.js/ nocase ascii wide
                        $string5_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\unzip\.exe/ nocase ascii wide
                        $string6_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\winagent\.exe/ nocase ascii wide
                        $string7_Nsight_RMM_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
                        $string8_Nsight_RMM_greyware_tool_keyword = /\\Program\sFiles\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
                        $string9_Nsight_RMM_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Advanced\sMonitoring\sAgent\.lnk/ nocase ascii wide
                        $string10_Nsight_RMM_greyware_tool_keyword = /Advanced\sMonitoring\sAgent\sHTTP\sRetriever\s1\.1/ nocase ascii wide

    condition:
        any of them
}