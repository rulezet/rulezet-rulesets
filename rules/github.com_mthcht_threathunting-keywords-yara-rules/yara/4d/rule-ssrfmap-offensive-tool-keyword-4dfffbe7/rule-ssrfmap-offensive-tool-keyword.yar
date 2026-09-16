rule rule_SSRFmap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SSRFmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSRFmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SSRFmap_offensive_tool_keyword = /\s\-r\sdata\/.{0,1000}\s\-p\s.{0,1000}\s\-m\sreadfiles.{0,1000}portscan/ nocase ascii wide
                        $string2_SSRFmap_offensive_tool_keyword = "/SSRFmap" nocase ascii wide
                        $string3_SSRFmap_offensive_tool_keyword = "SSRFmap" nocase ascii wide
                        $string4_SSRFmap_offensive_tool_keyword = /ssrfmap\.py/ nocase ascii wide

    condition:
        any of them
}