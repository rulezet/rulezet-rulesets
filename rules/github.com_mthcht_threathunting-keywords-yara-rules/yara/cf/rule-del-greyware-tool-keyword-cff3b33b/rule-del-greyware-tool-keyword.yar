rule rule_del_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'del' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "del"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_del_greyware_tool_keyword = /\sdel\sC\:\\Windows\\temp\\1\s\/F\s\/Q/ nocase ascii wide
                        $string2_del_greyware_tool_keyword = /del\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
                        $string3_del_greyware_tool_keyword = "del /f /s /q /a %AppData%" nocase ascii wide
                        $string4_del_greyware_tool_keyword = /del\sDefault\.rdp/ nocase ascii wide

    condition:
        any of them
}