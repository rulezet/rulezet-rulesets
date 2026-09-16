rule rule_Invoke_BuildAnonymousSMBServer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-BuildAnonymousSMBServer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-BuildAnonymousSMBServer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_BuildAnonymousSMBServer_offensive_tool_keyword = "Invoke-BuildAnonymousSMBServer -" nocase ascii wide
                        $string2_Invoke_BuildAnonymousSMBServer_offensive_tool_keyword = /Invoke\-BuildAnonymousSMBServer\.ps1/ nocase ascii wide

    condition:
        any of them
}