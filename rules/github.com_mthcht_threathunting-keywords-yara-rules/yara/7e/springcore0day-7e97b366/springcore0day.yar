rule SpringCore0day
{
    meta:
        description = "Detection patterns for the tool 'SpringCore0day' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpringCore0day"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/SpringCore0day" nocase ascii wide
                        $string2 = /curl\s\-\-output\s.{0,1000}http.{0,1000}\/tomcatwar\.jsp\?/ nocase ascii wide
                        $string3 = /python3\s\.\/exp\.py\s\-\-url\shttp\:\/\//
                        $string4 = "vulfocus/spring-core-rce-" nocase ascii wide

    condition:
        any of them
}