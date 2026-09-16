rule rule_SpringCore0day_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpringCore0day' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpringCore0day"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SpringCore0day_offensive_tool_keyword = "/SpringCore0day" nocase ascii wide
                        $string2_SpringCore0day_offensive_tool_keyword = /curl\s\-\-output\s.{0,1000}http.{0,1000}\/tomcatwar\.jsp\?/ nocase ascii wide
                        $string3_SpringCore0day_offensive_tool_keyword = /python3\s\.\/exp\.py\s\-\-url\shttp\:\/\//
                        $string4_SpringCore0day_offensive_tool_keyword = "vulfocus/spring-core-rce-" nocase ascii wide

    condition:
        any of them
}