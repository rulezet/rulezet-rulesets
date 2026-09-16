rule DumpKernel_S1_ps1
{
    meta:
        description = "Detection patterns for the tool 'DumpKernel-S1.ps1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpKernel-S1.ps1"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /C\:\\kernel\.dmp/ nocase ascii wide
                        $string2 = /DumpKernel\-S1\.ps1/ nocase ascii wide
                        $string3 = "Trying to dump kernel to C:" nocase ascii wide

    condition:
        any of them
}