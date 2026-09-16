rule rule_vncpwdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vncpwdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncpwdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_vncpwdump_offensive_tool_keyword = /\\vncdump\-/ nocase ascii wide
                        $string2_vncpwdump_offensive_tool_keyword = "vncdumpdll" nocase ascii wide
                        $string3_vncpwdump_offensive_tool_keyword = /vncpwdump\./ nocase ascii wide

    condition:
        any of them
}