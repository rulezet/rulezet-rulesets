rule csvde
{
    meta:
        description = "Detection patterns for the tool 'csvde' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "csvde"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "csvde -f " nocase ascii wide
                        $string2 = /csvde\s\-r\s.{0,1000}\s\-f\s/ nocase ascii wide
                        $string3 = /csvde\.exe\s\-f\s/ nocase ascii wide
                        $string4 = /csvde\.exe\s\-r\s.{0,1000}\s\-f\s/ nocase ascii wide
                        $string5 = /csvde\.exe\\"\s\-f\s/ nocase ascii wide

    condition:
        any of them
}