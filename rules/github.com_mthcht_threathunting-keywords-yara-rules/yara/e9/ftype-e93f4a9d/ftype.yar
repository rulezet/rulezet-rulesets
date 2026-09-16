rule ftype
{
    meta:
        description = "Detection patterns for the tool 'ftype' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ftype"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /ftype\s.{0,1000}findstr\s.{0,1000}dfil/ nocase ascii wide
                        $string2 = /ftype\s.{0,1000}findstr\s.{0,1000}SHCm/ nocase ascii wide
                        $string3 = /ftype\s.{0,1000}findstr\sdfil/ nocase ascii wide
                        $string4 = /ftype\s.{0,1000}findstr\sSHCm/ nocase ascii wide

    condition:
        any of them
}