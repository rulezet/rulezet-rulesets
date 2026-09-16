rule rule_PyExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PyExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PyExec_offensive_tool_keyword = /\sadm2sys\.py/ nocase ascii wide
                        $string2_PyExec_offensive_tool_keyword = /\/adm2sys\.py/ nocase ascii wide
                        $string3_PyExec_offensive_tool_keyword = /\/PyExec\.git/ nocase ascii wide
                        $string4_PyExec_offensive_tool_keyword = /\\adm2sys\.py/ nocase ascii wide
                        $string5_PyExec_offensive_tool_keyword = "OlivierLaflamme/PyExec" nocase ascii wide
                        $string6_PyExec_offensive_tool_keyword = /PyExec\-main\./ nocase ascii wide

    condition:
        any of them
}