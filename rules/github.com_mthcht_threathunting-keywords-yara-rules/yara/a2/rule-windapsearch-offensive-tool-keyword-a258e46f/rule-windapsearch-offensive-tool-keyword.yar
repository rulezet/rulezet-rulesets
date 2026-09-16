rule rule_windapsearch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'windapsearch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windapsearch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_windapsearch_offensive_tool_keyword = /\s\-d\s.{0,1000}\s\-u\s.{0,1000}\\.{0,1000}\s\-p\s.{0,1000}\s\-\-da/ nocase ascii wide
                        $string2_windapsearch_offensive_tool_keyword = " --unconstrained-users" nocase ascii wide
                        $string3_windapsearch_offensive_tool_keyword = " --user-spns" nocase ascii wide
                        $string4_windapsearch_offensive_tool_keyword = /\/windapsearch\.git/ nocase ascii wide
                        $string5_windapsearch_offensive_tool_keyword = /windapsearch\.py/ nocase ascii wide
                        $string6_windapsearch_offensive_tool_keyword = /windapsearch_py2\.py/ nocase ascii wide
                        $string7_windapsearch_offensive_tool_keyword = "windapsearch-master" nocase ascii wide

    condition:
        any of them
}