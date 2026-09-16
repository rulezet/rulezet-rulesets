rule ItWasAllADream
{
    meta:
        description = "Detection patterns for the tool 'ItWasAllADream' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ItWasAllADream"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ItWasAllADream\.git/ nocase ascii wide
                        $string2 = "byt3bl33d3r/ItWasAllADream" nocase ascii wide
                        $string3 = /itwasalladream\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-d\s/ nocase ascii wide
                        $string4 = /itwasalladream.{0,1000}bogus\.dll/ nocase ascii wide
                        $string5 = "ItWasAllADream-master" nocase ascii wide

    condition:
        any of them
}