rule rule_gato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gato_offensive_tool_keyword = /\/enumerate\/enumerate\.py/
                        $string2_gato_offensive_tool_keyword = /\/gato\/.{0,1000}attack\.py/ nocase ascii wide
                        $string3_gato_offensive_tool_keyword = /gato\s.{0,1000}\sattack/ nocase ascii wide
                        $string4_gato_offensive_tool_keyword = /gato\s.{0,1000}\senumerate/ nocase ascii wide
                        $string5_gato_offensive_tool_keyword = /gato\s.{0,1000}\s\-\-http\-proxy/ nocase ascii wide
                        $string6_gato_offensive_tool_keyword = /gato\s.{0,1000}\s\-\-socks\-proxy/ nocase ascii wide
                        $string7_gato_offensive_tool_keyword = "praetorian-inc/gato" nocase ascii wide

    condition:
        any of them
}