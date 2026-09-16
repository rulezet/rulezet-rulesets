rule AMSI_patch
{
    meta:
        description = "Detection patterns for the tool 'AMSI_patch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSI_patch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AMSI_patch\.git/ nocase ascii wide
                        $string2 = /\/AmsiOpenSession\.exe/ nocase ascii wide
                        $string3 = /AMS1\-Patch\.exe/ nocase ascii wide
                        $string4 = "AMSI_patch-main" nocase ascii wide
                        $string5 = /AmsiOpenSession\.cpp/ nocase ascii wide
                        $string6 = /AmsiOpenSession\.sln/ nocase ascii wide
                        $string7 = /AmsiOpenSession\.vcxproj/ nocase ascii wide
                        $string8 = "E09F4899-D8B3-4282-9E3A-B20EE9A3D463" nocase ascii wide
                        $string9 = "TheD1rkMtr/AMSI_patch" nocase ascii wide

    condition:
        any of them
}