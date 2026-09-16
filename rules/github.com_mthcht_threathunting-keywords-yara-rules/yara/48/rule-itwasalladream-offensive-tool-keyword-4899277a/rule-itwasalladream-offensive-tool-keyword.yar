rule rule_ItWasAllADream_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ItWasAllADream' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ItWasAllADream"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ItWasAllADream_offensive_tool_keyword = /\/ItWasAllADream\.git/ nocase ascii wide
                        $string2_ItWasAllADream_offensive_tool_keyword = "byt3bl33d3r/ItWasAllADream" nocase ascii wide
                        $string3_ItWasAllADream_offensive_tool_keyword = /itwasalladream\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-d\s/ nocase ascii wide
                        $string4_ItWasAllADream_offensive_tool_keyword = /itwasalladream.{0,1000}bogus\.dll/ nocase ascii wide
                        $string5_ItWasAllADream_offensive_tool_keyword = "ItWasAllADream-master" nocase ascii wide

    condition:
        any of them
}