rule padre
{
    meta:
        description = "Detection patterns for the tool 'padre' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "padre"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sgo\sbuild\s\-o\spadre\s\./ nocase ascii wide
                        $string2 = "/padre/pkg/exploit" nocase ascii wide
                        $string3 = /\\padre\\pkg\\exploit/ nocase ascii wide
                        $string4 = /github.{0,1000}\/padre\.git/ nocase ascii wide
                        $string5 = "glebarez/padre" nocase ascii wide
                        $string6 = "Gw3kg8e3ej4ai9wffn%2Fd0uRqKzyaPfM2UFq%2F8dWmoW4wnyKZhx07Bg==" nocase ascii wide
                        $string7 = "-p 5000:5000 pador_vuln_server" nocase ascii wide
                        $string8 = /padre\s\-u\s.{0,1000}http.{0,1000}\:\/\// nocase ascii wide
                        $string9 = /padre\-master\.zip/ nocase ascii wide

    condition:
        any of them
}