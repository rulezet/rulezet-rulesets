rule SSRFmap
{
    meta:
        description = "Detection patterns for the tool 'SSRFmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSRFmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-r\sdata\/.{0,1000}\s\-p\s.{0,1000}\s\-m\sreadfiles.{0,1000}portscan/ nocase ascii wide
                        $string2 = "/SSRFmap" nocase ascii wide
                        $string3 = "SSRFmap" nocase ascii wide
                        $string4 = /ssrfmap\.py/ nocase ascii wide

    condition:
        any of them
}