rule rule_SharpEventPersist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpEventPersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEventPersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpEventPersist_offensive_tool_keyword = /\/SharpEventPersist\.git/ nocase ascii wide
                        $string2_SharpEventPersist_offensive_tool_keyword = "27F85701-FD37-4D18-A107-20E914F8E779" nocase ascii wide
                        $string3_SharpEventPersist_offensive_tool_keyword = "7B4D3810-4A77-44A1-8546-779ACF02D083" nocase ascii wide
                        $string4_SharpEventPersist_offensive_tool_keyword = /\-file\s.{0,1000}\.bin\s\-instanceid\s1337\s\-\ssource\spersistence/ nocase ascii wide
                        $string5_SharpEventPersist_offensive_tool_keyword = "improsec/SharpEventPersist" nocase ascii wide
                        $string6_SharpEventPersist_offensive_tool_keyword = "SharpEventLoader" nocase ascii wide
                        $string7_SharpEventPersist_offensive_tool_keyword = /SharpEventLoader\.exe/ nocase ascii wide
                        $string8_SharpEventPersist_offensive_tool_keyword = "SharpEventPersist" nocase ascii wide
                        $string9_SharpEventPersist_offensive_tool_keyword = /SharpEventPersist\.exe/ nocase ascii wide
                        $string10_SharpEventPersist_offensive_tool_keyword = "SharpEventPersist-main" nocase ascii wide
                        $string11_SharpEventPersist_offensive_tool_keyword = /Specify\s\-instanceid\s1337.{0,1000}Specify\s\-source\s\'Persistence/ nocase ascii wide

    condition:
        any of them
}