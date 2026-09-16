rule rule_DueDLLigence_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DueDLLigence' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DueDLLigence"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DueDLLigence_offensive_tool_keyword = /\/DueDLLigence\.git/ nocase ascii wide
                        $string2_DueDLLigence_offensive_tool_keyword = /\\duedlligence\.dll/ nocase ascii wide
                        $string3_DueDLLigence_offensive_tool_keyword = "73948912-CEBD-48ED-85E2-85FCD1D4F560" nocase ascii wide
                        $string4_DueDLLigence_offensive_tool_keyword = /DueDLLigence\.cs/ nocase ascii wide
                        $string5_DueDLLigence_offensive_tool_keyword = /DueDLLigence\.sln/ nocase ascii wide
                        $string6_DueDLLigence_offensive_tool_keyword = "DueDLLigence-master" nocase ascii wide
                        $string7_DueDLLigence_offensive_tool_keyword = "mandiant/DueDLLigence" nocase ascii wide

    condition:
        any of them
}