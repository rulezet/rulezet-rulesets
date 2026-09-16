rule rule_csvde_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'csvde' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "csvde"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_csvde_greyware_tool_keyword = "csvde -f " nocase ascii wide
                        $string2_csvde_greyware_tool_keyword = /csvde\s\-r\s.{0,1000}\s\-f\s/ nocase ascii wide
                        $string3_csvde_greyware_tool_keyword = /csvde\.exe\s\-f\s/ nocase ascii wide
                        $string4_csvde_greyware_tool_keyword = /csvde\.exe\s\-r\s.{0,1000}\s\-f\s/ nocase ascii wide
                        $string5_csvde_greyware_tool_keyword = /csvde\.exe\\"\s\-f\s/ nocase ascii wide

    condition:
        any of them
}