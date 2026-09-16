rule spring_core_rce
{
    meta:
        description = "Detection patterns for the tool 'spring-core-rce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spring-core-rce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/spring-core-rce" nocase ascii wide
                        $string2 = /cat\s\.\/apache\-tomcat\-8\.5\.77\/webapps\/ROOT\/tomcatwar\.jsp/
                        $string3 = /github.{0,1000}\/Mr\-xn\// nocase ascii wide
                        $string4 = /spring\-core\-rce.{0,1000}ROOT\.war/ nocase ascii wide
                        $string5 = /target\/tomcatwar\.jsp\?pwd\=j\&cmd\=/ nocase ascii wide

    condition:
        any of them
}