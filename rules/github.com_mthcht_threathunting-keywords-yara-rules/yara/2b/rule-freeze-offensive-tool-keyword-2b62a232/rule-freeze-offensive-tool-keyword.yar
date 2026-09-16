rule rule_Freeze_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Freeze' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Freeze"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Freeze_offensive_tool_keyword = /\s\-encrypt\s.{0,1000}\s\-process\s.{0,1000}\s\-sandbox\s/ nocase ascii wide
                        $string2_Freeze_offensive_tool_keyword = "/optiv/Freeze/" nocase ascii wide
                        $string3_Freeze_offensive_tool_keyword = /\\freeze\.go/ nocase ascii wide
                        $string4_Freeze_offensive_tool_keyword = /build\sFreeze\.go/ nocase ascii wide
                        $string5_Freeze_offensive_tool_keyword = /Freeze_.{0,1000}_darwin_amd64/
                        $string6_Freeze_offensive_tool_keyword = /Freeze_.{0,1000}_linux_amd64/

    condition:
        any of them
}