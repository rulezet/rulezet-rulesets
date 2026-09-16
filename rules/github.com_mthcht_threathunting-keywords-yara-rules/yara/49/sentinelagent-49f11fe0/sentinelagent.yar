rule SentinelAgent
{
    meta:
        description = "Detection patterns for the tool 'SentinelAgent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SentinelAgent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sDumpS1\.ps1/ nocase ascii wide
                        $string2 = /\/DumpS1\.ps1/ nocase ascii wide
                        $string3 = /\\DumpS1\.ps1/ nocase ascii wide
                        $string4 = /\\temp\\__SentinelAgentKernel\.dmp/ nocase ascii wide
                        $string5 = /\\temp\\__SentinelAgentUser\.dmp/ nocase ascii wide
                        $string6 = /DumpProcessPid\s\-targetPID\s.{0,1000}\s\-outputFile/ nocase ascii wide
                        $string7 = /TakeDump\s\-SentinelHelper\s.{0,1000}\s\-ProcessId\s.{0,1000}\s\-User\s.{0,1000}\s\-Kernel\s/ nocase ascii wide
                        $string8 = "Trying to dump SentinelAgent to " nocase ascii wide

    condition:
        any of them
}