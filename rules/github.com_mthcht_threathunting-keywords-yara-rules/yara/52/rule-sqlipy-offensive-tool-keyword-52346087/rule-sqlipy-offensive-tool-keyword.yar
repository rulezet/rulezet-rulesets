rule rule_sqlipy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sqlipy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlipy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sqlipy_offensive_tool_keyword = /\/sqlmap\.zip/ nocase ascii wide
                        $string2_sqlipy_offensive_tool_keyword = "codewatchorg/sqlipy" nocase ascii wide
                        $string3_sqlipy_offensive_tool_keyword = /SQLiPy\.py/ nocase ascii wide
                        $string4_sqlipy_offensive_tool_keyword = /sqlmapapi\.py/ nocase ascii wide

    condition:
        any of them
}