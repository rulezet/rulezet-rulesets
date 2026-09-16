rule rule_SentinelAgent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SentinelAgent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SentinelAgent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_SentinelAgent_greyware_tool_keyword = /\sDumpS1\.ps1/ nocase ascii wide
                        $string2_SentinelAgent_greyware_tool_keyword = /\/DumpS1\.ps1/ nocase ascii wide
                        $string3_SentinelAgent_greyware_tool_keyword = /\\DumpS1\.ps1/ nocase ascii wide
                        $string4_SentinelAgent_greyware_tool_keyword = /\\temp\\__SentinelAgentKernel\.dmp/ nocase ascii wide
                        $string5_SentinelAgent_greyware_tool_keyword = /\\temp\\__SentinelAgentUser\.dmp/ nocase ascii wide
                        $string6_SentinelAgent_greyware_tool_keyword = /DumpProcessPid\s\-targetPID\s.{0,1000}\s\-outputFile/ nocase ascii wide
                        $string7_SentinelAgent_greyware_tool_keyword = /TakeDump\s\-SentinelHelper\s.{0,1000}\s\-ProcessId\s.{0,1000}\s\-User\s.{0,1000}\s\-Kernel\s/ nocase ascii wide
                        $string8_SentinelAgent_greyware_tool_keyword = "Trying to dump SentinelAgent to " nocase ascii wide

    condition:
        any of them
}