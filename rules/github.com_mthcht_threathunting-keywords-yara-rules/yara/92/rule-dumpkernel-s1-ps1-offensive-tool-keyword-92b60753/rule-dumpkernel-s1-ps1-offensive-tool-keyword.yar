rule rule_DumpKernel_S1_ps1_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DumpKernel-S1.ps1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpKernel-S1.ps1"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DumpKernel_S1_ps1_offensive_tool_keyword = /C\:\\kernel\.dmp/ nocase ascii wide
                        $string2_DumpKernel_S1_ps1_offensive_tool_keyword = /DumpKernel\-S1\.ps1/ nocase ascii wide
                        $string3_DumpKernel_S1_ps1_offensive_tool_keyword = "Trying to dump kernel to C:" nocase ascii wide

    condition:
        any of them
}