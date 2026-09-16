rule rule_Invoke_WMIpersist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-WMIpersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-WMIpersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_WMIpersist_offensive_tool_keyword = "8d3945448815d156c064445585aa7cf51a5c30e9f96d7598e8ca323815f9aee3" nocase ascii wide
                        $string2_Invoke_WMIpersist_offensive_tool_keyword = "Invoke-WMIpersist" nocase ascii wide
                        $string3_Invoke_WMIpersist_offensive_tool_keyword = /Invoke\-WMIpersist\.ps1/ nocase ascii wide

    condition:
        any of them
}