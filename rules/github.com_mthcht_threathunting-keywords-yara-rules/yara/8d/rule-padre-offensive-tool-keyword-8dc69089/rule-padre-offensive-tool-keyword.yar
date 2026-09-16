rule rule_padre_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'padre' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "padre"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_padre_offensive_tool_keyword = /\sgo\sbuild\s\-o\spadre\s\./ nocase ascii wide
                        $string2_padre_offensive_tool_keyword = "/padre/pkg/exploit" nocase ascii wide
                        $string3_padre_offensive_tool_keyword = /\\padre\\pkg\\exploit/ nocase ascii wide
                        $string4_padre_offensive_tool_keyword = /github.{0,1000}\/padre\.git/ nocase ascii wide
                        $string5_padre_offensive_tool_keyword = "glebarez/padre" nocase ascii wide
                        $string6_padre_offensive_tool_keyword = "Gw3kg8e3ej4ai9wffn%2Fd0uRqKzyaPfM2UFq%2F8dWmoW4wnyKZhx07Bg==" nocase ascii wide
                        $string7_padre_offensive_tool_keyword = "-p 5000:5000 pador_vuln_server" nocase ascii wide
                        $string8_padre_offensive_tool_keyword = /padre\s\-u\s.{0,1000}http.{0,1000}\:\/\// nocase ascii wide
                        $string9_padre_offensive_tool_keyword = /padre\-master\.zip/ nocase ascii wide

    condition:
        any of them
}