rule sqlipy
{
    meta:
        description = "Detection patterns for the tool 'sqlipy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlipy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/sqlmap\.zip/ nocase ascii wide
                        $string2 = "codewatchorg/sqlipy" nocase ascii wide
                        $string3 = /SQLiPy\.py/ nocase ascii wide
                        $string4 = /sqlmapapi\.py/ nocase ascii wide

    condition:
        any of them
}