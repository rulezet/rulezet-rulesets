rule del
{
    meta:
        description = "Detection patterns for the tool 'del' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "del"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sdel\sC\:\\Windows\\temp\\1\s\/F\s\/Q/ nocase ascii wide
                        $string2 = /del\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
                        $string3 = "del /f /s /q /a %AppData%" nocase ascii wide
                        $string4 = /del\sDefault\.rdp/ nocase ascii wide

    condition:
        any of them
}