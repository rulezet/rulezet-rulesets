rule rule_psgetsystem_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'psgetsystem' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psgetsystem"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_psgetsystem_offensive_tool_keyword = /\spsgetsys\.ps1/ nocase ascii wide
                        $string2_psgetsystem_offensive_tool_keyword = /\/psgetsys\.ps1/ nocase ascii wide
                        $string3_psgetsystem_offensive_tool_keyword = /\/psgetsystem\.git/ nocase ascii wide
                        $string4_psgetsystem_offensive_tool_keyword = /\:CreateProcessFromParent\(\(Get\-Process\s\\"lsass\\"\)\.Id/ nocase ascii wide
                        $string5_psgetsystem_offensive_tool_keyword = /\\psgetsys\.ps1/ nocase ascii wide
                        $string6_psgetsystem_offensive_tool_keyword = "decoder-it/psgetsystem" nocase ascii wide
                        $string7_psgetsystem_offensive_tool_keyword = "function ImpersonateFromParentPid" nocase ascii wide
                        $string8_psgetsystem_offensive_tool_keyword = "ImpersonateFromParentPid -ppid" nocase ascii wide
                        $string9_psgetsystem_offensive_tool_keyword = "Simple powershell/C# to spawn a process under a different parent process" nocase ascii wide

    condition:
        any of them
}