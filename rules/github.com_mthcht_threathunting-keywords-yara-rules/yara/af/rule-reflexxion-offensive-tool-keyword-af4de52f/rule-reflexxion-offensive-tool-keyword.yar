rule rule_RefleXXion_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RefleXXion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RefleXXion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RefleXXion_offensive_tool_keyword = /\/RefleXXion\.git/ nocase ascii wide
                        $string2_RefleXXion_offensive_tool_keyword = "hlldz/RefleXXion" nocase ascii wide
                        $string3_RefleXXion_offensive_tool_keyword = /RefleXXion.{0,1000}ntdll\.dll/ nocase ascii wide
                        $string4_RefleXXion_offensive_tool_keyword = /RefleXXion\.sln/ nocase ascii wide
                        $string5_RefleXXion_offensive_tool_keyword = "RefleXXion-DLL" nocase ascii wide
                        $string6_RefleXXion_offensive_tool_keyword = "RefleXXion-EXE" nocase ascii wide
                        $string7_RefleXXion_offensive_tool_keyword = "RefleXXion-main" nocase ascii wide

    condition:
        any of them
}