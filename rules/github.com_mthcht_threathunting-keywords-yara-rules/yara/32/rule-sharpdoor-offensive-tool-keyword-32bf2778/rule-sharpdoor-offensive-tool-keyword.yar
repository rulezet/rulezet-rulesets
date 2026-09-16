rule rule_SharpDoor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpDoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpDoor_offensive_tool_keyword = /\sSharpDoor\.cs/ nocase ascii wide
                        $string2_SharpDoor_offensive_tool_keyword = /\sSharpDoor\.exe/ nocase ascii wide
                        $string3_SharpDoor_offensive_tool_keyword = /\/SharpDoor\.cs/ nocase ascii wide
                        $string4_SharpDoor_offensive_tool_keyword = /\/SharpDoor\.exe/ nocase ascii wide
                        $string5_SharpDoor_offensive_tool_keyword = /\/SharpDoor\.git/ nocase ascii wide
                        $string6_SharpDoor_offensive_tool_keyword = /\/SharpDoor\.git/ nocase ascii wide
                        $string7_SharpDoor_offensive_tool_keyword = /\[\!\]\sUnhandled\sSharpDoor\sexception/ nocase ascii wide
                        $string8_SharpDoor_offensive_tool_keyword = /\\SharpDoor\.cs/ nocase ascii wide
                        $string9_SharpDoor_offensive_tool_keyword = /\\SharpDoor\.exe/ nocase ascii wide
                        $string10_SharpDoor_offensive_tool_keyword = /\\termsrv\.patch\.dll/ nocase ascii wide
                        $string11_SharpDoor_offensive_tool_keyword = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
                        $string12_SharpDoor_offensive_tool_keyword = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
                        $string13_SharpDoor_offensive_tool_keyword = /\\Users\\Public\\termsrv\.patch\.dll/ nocase ascii wide
                        $string14_SharpDoor_offensive_tool_keyword = "4cec28b4c00002245dffc8346be0cc11" nocase ascii wide
                        $string15_SharpDoor_offensive_tool_keyword = /Allow\sMultiple\sRDP\s\(Remote\sDesktop\)\sSessions\sBy\sPatching\stermsrv\.dll\sFile/ nocase ascii wide
                        $string16_SharpDoor_offensive_tool_keyword = "infosecn1nja/SharpDoor" nocase ascii wide
                        $string17_SharpDoor_offensive_tool_keyword = "infosecn1nja/SharpDoor" nocase ascii wide
                        $string18_SharpDoor_offensive_tool_keyword = /SharpDoor\.exe/ nocase ascii wide
                        $string19_SharpDoor_offensive_tool_keyword = "SharpDoor-master" nocase ascii wide
                        $string20_SharpDoor_offensive_tool_keyword = "SharpDoor-master" nocase ascii wide

    condition:
        any of them
}