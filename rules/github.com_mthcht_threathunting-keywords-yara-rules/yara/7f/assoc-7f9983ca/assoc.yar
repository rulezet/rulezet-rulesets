rule assoc
{
    meta:
        description = "Detection patterns for the tool 'assoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "assoc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /assoc\s.{0,1000}findstr\s.{0,1000}\=cm/ nocase ascii wide
                        $string2 = /assoc\s.{0,1000}findstr\s.{0,1000}lCmd/ nocase ascii wide
                        $string3 = /assoc\s.{0,1000}findstr\s.{0,1000}mdf/ nocase ascii wide
                        $string4 = /assoc\s.{0,1000}findstr\s.{0,1000}s1x/ nocase ascii wide
                        $string5 = /assoc\s.{0,1000}findstr\s\=cm/ nocase ascii wide
                        $string6 = /assoc\s.{0,1000}findstr\slCmd/ nocase ascii wide
                        $string7 = /assoc\s.{0,1000}findstr\smdf/ nocase ascii wide
                        $string8 = /assoc\s.{0,1000}findstr\ss1x/ nocase ascii wide

    condition:
        any of them
}