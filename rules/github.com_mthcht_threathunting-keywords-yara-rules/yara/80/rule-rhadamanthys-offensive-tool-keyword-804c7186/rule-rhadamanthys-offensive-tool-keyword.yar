rule rule_Rhadamanthys_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Rhadamanthys' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rhadamanthys"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Rhadamanthys_offensive_tool_keyword = " Xworm v" nocase ascii wide
                        $string2_Rhadamanthys_offensive_tool_keyword = /\/XWorm\.exe/ nocase ascii wide
                        $string3_Rhadamanthys_offensive_tool_keyword = /\/XWorm\.rar/
                        $string4_Rhadamanthys_offensive_tool_keyword = /\\XKlog\.txt/ nocase ascii wide
                        $string5_Rhadamanthys_offensive_tool_keyword = /\\XWorm\.config/ nocase ascii wide
                        $string6_Rhadamanthys_offensive_tool_keyword = /\\XWorm\.exe/ nocase ascii wide
                        $string7_Rhadamanthys_offensive_tool_keyword = /\\XWorm\.rar/ nocase ascii wide
                        $string8_Rhadamanthys_offensive_tool_keyword = "9950788284df125c7359aeb91435ed24d59359fac6a74ed73774ca31561cc7ae" nocase ascii wide
                        $string9_Rhadamanthys_offensive_tool_keyword = "XWorm-v5-Remote-Access-Tool" nocase ascii wide

    condition:
        any of them
}