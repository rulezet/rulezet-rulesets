rule rule_AMSI_patch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AMSI_patch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSI_patch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AMSI_patch_offensive_tool_keyword = /\/AMSI_patch\.git/ nocase ascii wide
                        $string2_AMSI_patch_offensive_tool_keyword = /\/AmsiOpenSession\.exe/ nocase ascii wide
                        $string3_AMSI_patch_offensive_tool_keyword = /AMS1\-Patch\.exe/ nocase ascii wide
                        $string4_AMSI_patch_offensive_tool_keyword = "AMSI_patch-main" nocase ascii wide
                        $string5_AMSI_patch_offensive_tool_keyword = /AmsiOpenSession\.cpp/ nocase ascii wide
                        $string6_AMSI_patch_offensive_tool_keyword = /AmsiOpenSession\.sln/ nocase ascii wide
                        $string7_AMSI_patch_offensive_tool_keyword = /AmsiOpenSession\.vcxproj/ nocase ascii wide
                        $string8_AMSI_patch_offensive_tool_keyword = "E09F4899-D8B3-4282-9E3A-B20EE9A3D463" nocase ascii wide
                        $string9_AMSI_patch_offensive_tool_keyword = "TheD1rkMtr/AMSI_patch" nocase ascii wide

    condition:
        any of them
}