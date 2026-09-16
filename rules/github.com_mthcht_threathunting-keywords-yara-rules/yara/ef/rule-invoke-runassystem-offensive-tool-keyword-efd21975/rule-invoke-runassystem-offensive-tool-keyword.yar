rule rule_Invoke_RunAsSystem_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-RunAsSystem' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-RunAsSystem"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_RunAsSystem_offensive_tool_keyword = /\/Invoke\-RunAsSystem\.git/ nocase ascii wide
                        $string2_Invoke_RunAsSystem_offensive_tool_keyword = "5f685def3707cb4737e0e520d86b05a0c7c7d973c9b0d26b89dddd9f1d615404" nocase ascii wide
                        $string3_Invoke_RunAsSystem_offensive_tool_keyword = /Invoke\-RunAsSystem\.ps1/ nocase ascii wide
                        $string4_Invoke_RunAsSystem_offensive_tool_keyword = "Leo4j/Invoke-RunAsSystem" nocase ascii wide

    condition:
        any of them
}