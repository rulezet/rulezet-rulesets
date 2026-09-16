rule goMatrixC2
{
    meta:
        description = "Detection patterns for the tool 'goMatrixC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goMatrixC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AntiSandbox\.go/ nocase ascii wide
                        $string2 = /\/goMatrixC2\.git/ nocase ascii wide
                        $string3 = /\\AntiSandbox\.go/ nocase ascii wide
                        $string4 = /goMatrixC2\.go/ nocase ascii wide
                        $string5 = "goMatrixC2-main" nocase ascii wide
                        $string6 = "n1k7l4i/goMatrixC2" nocase ascii wide

    condition:
        any of them
}