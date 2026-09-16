rule rule_goZulipC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'goZulipC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goZulipC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_goZulipC2_offensive_tool_keyword = /\/AntiSandbox\.go/ nocase ascii wide
                        $string2_goZulipC2_offensive_tool_keyword = /\/goZulipC2\.git/ nocase ascii wide
                        $string3_goZulipC2_offensive_tool_keyword = /\\AntiSandbox\.go/ nocase ascii wide
                        $string4_goZulipC2_offensive_tool_keyword = /\\goZulipC2/ nocase ascii wide
                        $string5_goZulipC2_offensive_tool_keyword = /goZulipC2\.go/ nocase ascii wide
                        $string6_goZulipC2_offensive_tool_keyword = "goZulipC2-main" nocase ascii wide
                        $string7_goZulipC2_offensive_tool_keyword = "n1k7l4i/goZulipC2" nocase ascii wide

    condition:
        any of them
}