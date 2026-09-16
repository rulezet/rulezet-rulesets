rule rule_sysmonquiet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sysmonquiet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sysmonquiet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sysmonquiet_offensive_tool_keyword = "/SysmonQuiet" nocase ascii wide
                        $string2_sysmonquiet_offensive_tool_keyword = "Sysmon is being suffocated" nocase ascii wide
                        $string3_sysmonquiet_offensive_tool_keyword = "Sysmon is quiet now!" nocase ascii wide
                        $string4_sysmonquiet_offensive_tool_keyword = /sysmonquiet\./ nocase ascii wide
                        $string5_sysmonquiet_offensive_tool_keyword = "SysmonQuiet-main" nocase ascii wide
                        $string6_sysmonquiet_offensive_tool_keyword = "Yay! No SYSMON here!" nocase ascii wide

    condition:
        any of them
}