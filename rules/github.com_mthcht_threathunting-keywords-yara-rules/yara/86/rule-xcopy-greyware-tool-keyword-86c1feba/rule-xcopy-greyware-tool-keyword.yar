rule rule_xcopy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xcopy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xcopy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_xcopy_greyware_tool_keyword = "cmd /c xcopy /s /i /h /e /q /y /d" nocase ascii wide
                        $string2_xcopy_greyware_tool_keyword = /xcopy\s\/Y\s\/C\s\/Q\sC\:\\Windows\\system32\\.{0,1000}\.exe\s.{0,1000}Ie4uinit\.exe/ nocase ascii wide
                        $string3_xcopy_greyware_tool_keyword = /xcopy\sc\:\\.{0,1000}\s\\\\.{0,1000}\\c\$/ nocase ascii wide

    condition:
        any of them
}