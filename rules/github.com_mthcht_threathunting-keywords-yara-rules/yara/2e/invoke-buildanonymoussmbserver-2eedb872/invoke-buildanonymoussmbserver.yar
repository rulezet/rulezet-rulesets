rule Invoke_BuildAnonymousSMBServer
{
    meta:
        description = "Detection patterns for the tool 'Invoke-BuildAnonymousSMBServer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-BuildAnonymousSMBServer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Invoke-BuildAnonymousSMBServer -" nocase ascii wide
                        $string2 = /Invoke\-BuildAnonymousSMBServer\.ps1/ nocase ascii wide

    condition:
        any of them
}