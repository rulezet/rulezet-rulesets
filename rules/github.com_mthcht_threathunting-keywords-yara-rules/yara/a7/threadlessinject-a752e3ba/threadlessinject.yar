rule ThreadlessInject
{
    meta:
        description = "Detection patterns for the tool 'ThreadlessInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThreadlessInject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-p\s.{0,1000}\s\-d\s.{0,1000}\.dll\s\-e\sOpenProcess/ nocase ascii wide
                        $string2 = /\/ThreadlessInject\.git/ nocase ascii wide
                        $string3 = "CCob/ThreadlessInject" nocase ascii wide
                        $string4 = /Needles\swithout\sthe\sThread\.pptx/ nocase ascii wide
                        $string5 = /ThreadlessInject.{0,1000}\s\-p\s.{0,1000}\s\-d\s/ nocase ascii wide
                        $string6 = /ThreadlessInject\.exe/ nocase ascii wide
                        $string7 = "ThreadlessInject-master" nocase ascii wide

    condition:
        any of them
}