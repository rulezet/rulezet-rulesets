rule rule_SharpDllProxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpDllProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDllProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpDllProxy_offensive_tool_keyword = /\s\-\-dll\s.{0,1000}\s\-\-payload\s/ nocase ascii wide
                        $string2_SharpDllProxy_offensive_tool_keyword = "676E89F3-4785-477A-BA1C-B30340F598D5" nocase ascii wide
                        $string3_SharpDllProxy_offensive_tool_keyword = "7a8cabbb37d569b2d9af56a4a11bb83dc5bb839c3d4a3ea05252e20e2d0c3a45" nocase ascii wide
                        $string4_SharpDllProxy_offensive_tool_keyword = "SharpDllProxy" nocase ascii wide

    condition:
        any of them
}