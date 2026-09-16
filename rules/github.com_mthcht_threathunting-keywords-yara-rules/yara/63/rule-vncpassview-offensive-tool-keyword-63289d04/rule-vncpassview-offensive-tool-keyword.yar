rule rule_VNCPassView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VNCPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VNCPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_VNCPassView_offensive_tool_keyword = /\/utils\/vnc_password\.html/ nocase ascii wide
                        $string2_VNCPassView_offensive_tool_keyword = ">VNCPassView<" nocase ascii wide
                        $string3_VNCPassView_offensive_tool_keyword = "816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019" nocase ascii wide
                        $string4_VNCPassView_offensive_tool_keyword = "cba64638575e382bab065f43dc60b76943bce77854a80af38debeb803edb96e4" nocase ascii wide

    condition:
        any of them
}