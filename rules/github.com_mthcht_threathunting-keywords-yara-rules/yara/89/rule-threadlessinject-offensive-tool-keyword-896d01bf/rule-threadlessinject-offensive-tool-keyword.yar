rule rule_ThreadlessInject_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ThreadlessInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThreadlessInject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ThreadlessInject_offensive_tool_keyword = /\s\-p\s.{0,1000}\s\-d\s.{0,1000}\.dll\s\-e\sOpenProcess/ nocase ascii wide
                        $string2_ThreadlessInject_offensive_tool_keyword = /\/ThreadlessInject\.git/ nocase ascii wide
                        $string3_ThreadlessInject_offensive_tool_keyword = "CCob/ThreadlessInject" nocase ascii wide
                        $string4_ThreadlessInject_offensive_tool_keyword = /Needles\swithout\sthe\sThread\.pptx/ nocase ascii wide
                        $string5_ThreadlessInject_offensive_tool_keyword = /ThreadlessInject.{0,1000}\s\-p\s.{0,1000}\s\-d\s/ nocase ascii wide
                        $string6_ThreadlessInject_offensive_tool_keyword = /ThreadlessInject\.exe/ nocase ascii wide
                        $string7_ThreadlessInject_offensive_tool_keyword = "ThreadlessInject-master" nocase ascii wide

    condition:
        any of them
}