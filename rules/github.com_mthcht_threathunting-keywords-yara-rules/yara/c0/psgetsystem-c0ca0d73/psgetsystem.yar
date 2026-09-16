rule psgetsystem
{
    meta:
        description = "Detection patterns for the tool 'psgetsystem' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psgetsystem"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\spsgetsys\.ps1/ nocase ascii wide
                        $string2 = /\/psgetsys\.ps1/ nocase ascii wide
                        $string3 = /\/psgetsystem\.git/ nocase ascii wide
                        $string4 = /\:CreateProcessFromParent\(\(Get\-Process\s\\"lsass\\"\)\.Id/ nocase ascii wide
                        $string5 = /\\psgetsys\.ps1/ nocase ascii wide
                        $string6 = "decoder-it/psgetsystem" nocase ascii wide
                        $string7 = "function ImpersonateFromParentPid" nocase ascii wide
                        $string8 = "ImpersonateFromParentPid -ppid" nocase ascii wide
                        $string9 = "Simple powershell/C# to spawn a process under a different parent process" nocase ascii wide

    condition:
        any of them
}