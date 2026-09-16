rule rule_ftype_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ftype' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ftype"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\s.{0,1000}dfil/ nocase ascii wide
                        $string2_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\s.{0,1000}SHCm/ nocase ascii wide
                        $string3_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\sdfil/ nocase ascii wide
                        $string4_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\sSHCm/ nocase ascii wide

    condition:
        any of them
}