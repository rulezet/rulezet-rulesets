rule rule_megatools_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'megatools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "megatools"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_megatools_greyware_tool_keyword = /\/megatools\.exe/ nocase ascii wide
                        $string2_megatools_greyware_tool_keyword = /\\\.megatools\.cache/ nocase ascii wide
                        $string3_megatools_greyware_tool_keyword = /\\megatools\-.{0,1000}\-win64\\/ nocase ascii wide
                        $string4_megatools_greyware_tool_keyword = /\\megatools\.exe/ nocase ascii wide
                        $string5_megatools_greyware_tool_keyword = /\\Users\\.{0,1000}\\AppData\\Local\\Temp\\.{0,1000}\.megatools\.cache/ nocase ascii wide
                        $string6_megatools_greyware_tool_keyword = /megatools\scopy\s\-l\s.{0,1000}\s\-r\s/ nocase ascii wide
                        $string7_megatools_greyware_tool_keyword = "megatools put " nocase ascii wide

    condition:
        any of them
}