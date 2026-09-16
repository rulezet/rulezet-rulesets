rule findstr
{
    meta:
        description = "Detection patterns for the tool 'findstr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findstr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /findstr\s.{0,1000}BEGIN\sCERTIFICATE/ nocase ascii wide
                        $string2 = /findstr\s.{0,1000}confidential/ nocase ascii wide
                        $string3 = /findstr\s.{0,1000}net\suse/ nocase ascii wide
                        $string4 = /findstr\s.{0,1000}password/ nocase ascii wide
                        $string5 = /findstr\s\/S\s\/I\scpassword\s.{0,1000}\\policies\\.{0,1000}\.xml/ nocase ascii wide
                        $string6 = "findstr lsass" nocase ascii wide

    condition:
        any of them
}