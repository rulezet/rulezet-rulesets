rule rule_MSOLSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MSOLSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSOLSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MSOLSpray_offensive_tool_keyword = "/MSOLSpray" nocase ascii wide
                        $string2_MSOLSpray_offensive_tool_keyword = "MSOLSpray " nocase ascii wide
                        $string3_MSOLSpray_offensive_tool_keyword = /MSOLSpray\.git/ nocase ascii wide
                        $string4_MSOLSpray_offensive_tool_keyword = /MSOLSpray\.ps1/ nocase ascii wide
                        $string5_MSOLSpray_offensive_tool_keyword = "MSOLSpray-master" nocase ascii wide

    condition:
        any of them
}