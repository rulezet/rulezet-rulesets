rule rule_dazzleUP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dazzleUP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dazzleUP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dazzleUP_offensive_tool_keyword = /\/dazzleUP\.git/ nocase ascii wide
                        $string2_dazzleUP_offensive_tool_keyword = /dazzleUP\.cna/ nocase ascii wide
                        $string3_dazzleUP_offensive_tool_keyword = /dazzleUP\.exe/ nocase ascii wide
                        $string4_dazzleUP_offensive_tool_keyword = /dazzleUP\.sln/ nocase ascii wide
                        $string5_dazzleUP_offensive_tool_keyword = /dazzleUP\.vcxproj/ nocase ascii wide
                        $string6_dazzleUP_offensive_tool_keyword = /dazzleUP\.x32\.exe/ nocase ascii wide
                        $string7_dazzleUP_offensive_tool_keyword = /dazzleUP\.x64\.exe/ nocase ascii wide
                        $string8_dazzleUP_offensive_tool_keyword = "dazzleUP_Reflective_DLL" nocase ascii wide
                        $string9_dazzleUP_offensive_tool_keyword = "dazzleUP-master" nocase ascii wide
                        $string10_dazzleUP_offensive_tool_keyword = "FE8F0D23-BDD1-416D-8285-F947BA86D155" nocase ascii wide
                        $string11_dazzleUP_offensive_tool_keyword = "hlldz/dazzleUP" nocase ascii wide
                        $string12_dazzleUP_offensive_tool_keyword = /path_dll_hijack\.h/ nocase ascii wide

    condition:
        any of them
}