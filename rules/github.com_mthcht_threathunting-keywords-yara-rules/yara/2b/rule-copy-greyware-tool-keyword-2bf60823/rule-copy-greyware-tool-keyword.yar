rule rule_copy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'copy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "copy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_copy_greyware_tool_keyword = /copy\s.{0,1000}\.exe\s\\\\.{0,1000}\\c\$\\Windows\\.{0,1000}\.exe/ nocase ascii wide
                        $string2_copy_greyware_tool_keyword = /copy\s.{0,1000}\\NTDS\\ntds\.dit\s.{0,1000}\\Temp\\.{0,1000}\./ nocase ascii wide
                        $string3_copy_greyware_tool_keyword = /copy\s.{0,1000}NTDS\\NTDS\.dit.{0,1000}Temp/ nocase ascii wide
                        $string4_copy_greyware_tool_keyword = /copy.{0,1000}C\:\\ProgramData\\.{0,1000}\.dll.{0,1000}\\c\$\\/ nocase ascii wide

    condition:
        any of them
}