rule RefleXXion
{
    meta:
        description = "Detection patterns for the tool 'RefleXXion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RefleXXion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/RefleXXion\.git/ nocase ascii wide
                        $string2 = "hlldz/RefleXXion" nocase ascii wide
                        $string3 = /RefleXXion.{0,1000}ntdll\.dll/ nocase ascii wide
                        $string4 = /RefleXXion\.sln/ nocase ascii wide
                        $string5 = "RefleXXion-DLL" nocase ascii wide
                        $string6 = "RefleXXion-EXE" nocase ascii wide
                        $string7 = "RefleXXion-main" nocase ascii wide

    condition:
        any of them
}