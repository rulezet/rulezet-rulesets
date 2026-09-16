rule PyExec
{
    meta:
        description = "Detection patterns for the tool 'PyExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sadm2sys\.py/ nocase ascii wide
                        $string2 = /\/adm2sys\.py/ nocase ascii wide
                        $string3 = /\/PyExec\.git/ nocase ascii wide
                        $string4 = /\\adm2sys\.py/ nocase ascii wide
                        $string5 = "OlivierLaflamme/PyExec" nocase ascii wide
                        $string6 = /PyExec\-main\./ nocase ascii wide

    condition:
        any of them
}