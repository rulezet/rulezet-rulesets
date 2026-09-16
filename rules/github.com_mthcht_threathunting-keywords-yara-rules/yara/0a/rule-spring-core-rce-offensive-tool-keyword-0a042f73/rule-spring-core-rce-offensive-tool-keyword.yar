rule rule_spring_core_rce_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spring-core-rce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spring-core-rce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spring_core_rce_offensive_tool_keyword = "/spring-core-rce" nocase ascii wide
                        $string2_spring_core_rce_offensive_tool_keyword = /cat\s\.\/apache\-tomcat\-8\.5\.77\/webapps\/ROOT\/tomcatwar\.jsp/
                        $string3_spring_core_rce_offensive_tool_keyword = /github.{0,1000}\/Mr\-xn\// nocase ascii wide
                        $string4_spring_core_rce_offensive_tool_keyword = /spring\-core\-rce.{0,1000}ROOT\.war/ nocase ascii wide
                        $string5_spring_core_rce_offensive_tool_keyword = /target\/tomcatwar\.jsp\?pwd\=j\&cmd\=/ nocase ascii wide

    condition:
        any of them
}