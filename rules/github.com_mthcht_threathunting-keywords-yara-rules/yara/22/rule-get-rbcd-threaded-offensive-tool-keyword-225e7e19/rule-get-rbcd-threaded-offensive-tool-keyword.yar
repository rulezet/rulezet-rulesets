rule rule_Get_RBCD_Threaded_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Get-RBCD-Threaded' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-RBCD-Threaded"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Get_RBCD_Threaded_offensive_tool_keyword = /\.exe\s.{0,1000}\-searchforest.{0,1000}\-pwdlastset/ nocase ascii wide
                        $string2_Get_RBCD_Threaded_offensive_tool_keyword = "Get-RBCD-Threaded" nocase ascii wide

    condition:
        any of them
}