rule rule_goMatrixC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'goMatrixC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goMatrixC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_goMatrixC2_offensive_tool_keyword = /\/AntiSandbox\.go/ nocase ascii wide
                        $string2_goMatrixC2_offensive_tool_keyword = /\/goMatrixC2\.git/ nocase ascii wide
                        $string3_goMatrixC2_offensive_tool_keyword = /\\AntiSandbox\.go/ nocase ascii wide
                        $string4_goMatrixC2_offensive_tool_keyword = /goMatrixC2\.go/ nocase ascii wide
                        $string5_goMatrixC2_offensive_tool_keyword = "goMatrixC2-main" nocase ascii wide
                        $string6_goMatrixC2_offensive_tool_keyword = "n1k7l4i/goMatrixC2" nocase ascii wide

    condition:
        any of them
}