rule dazzleUP
{
    meta:
        description = "Detection patterns for the tool 'dazzleUP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dazzleUP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/dazzleUP\.git/ nocase ascii wide
                        $string2 = /dazzleUP\.cna/ nocase ascii wide
                        $string3 = /dazzleUP\.exe/ nocase ascii wide
                        $string4 = /dazzleUP\.sln/ nocase ascii wide
                        $string5 = /dazzleUP\.vcxproj/ nocase ascii wide
                        $string6 = /dazzleUP\.x32\.exe/ nocase ascii wide
                        $string7 = /dazzleUP\.x64\.exe/ nocase ascii wide
                        $string8 = "dazzleUP_Reflective_DLL" nocase ascii wide
                        $string9 = "dazzleUP-master" nocase ascii wide
                        $string10 = "FE8F0D23-BDD1-416D-8285-F947BA86D155" nocase ascii wide
                        $string11 = "hlldz/dazzleUP" nocase ascii wide
                        $string12 = /path_dll_hijack\.h/ nocase ascii wide

    condition:
        any of them
}