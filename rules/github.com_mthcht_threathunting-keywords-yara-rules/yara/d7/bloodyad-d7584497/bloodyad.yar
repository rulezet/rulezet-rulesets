rule bloodyAD
{
    meta:
        description = "Detection patterns for the tool 'bloodyAD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bloodyAD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/bloodyAD\.git/ nocase ascii wide
                        $string2 = "bloodyAD -" nocase ascii wide
                        $string3 = /bloodyAD\.py/ nocase ascii wide
                        $string4 = "bloodyAD-main" nocase ascii wide
                        $string5 = "CravateRouge/bloodyAD" nocase ascii wide

    condition:
        any of them
}