rule windapsearch
{
    meta:
        description = "Detection patterns for the tool 'windapsearch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windapsearch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-d\s.{0,1000}\s\-u\s.{0,1000}\\.{0,1000}\s\-p\s.{0,1000}\s\-\-da/ nocase ascii wide
                        $string2 = " --unconstrained-users" nocase ascii wide
                        $string3 = " --user-spns" nocase ascii wide
                        $string4 = /\/windapsearch\.git/ nocase ascii wide
                        $string5 = /windapsearch\.py/ nocase ascii wide
                        $string6 = /windapsearch_py2\.py/ nocase ascii wide
                        $string7 = "windapsearch-master" nocase ascii wide

    condition:
        any of them
}