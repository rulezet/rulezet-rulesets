rule Mshikaki
{
    meta:
        description = "Detection patterns for the tool 'Mshikaki' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mshikaki"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sMshikaki\.cpp/ nocase ascii wide
                        $string2 = /\/Mshikaki\.git/ nocase ascii wide
                        $string3 = /\\Mshikaki\.cpp/ nocase ascii wide
                        $string4 = /Mshikaki\.exe/ nocase ascii wide
                        $string5 = "Mshikaki-main" nocase ascii wide
                        $string6 = "trevorsaudi/Mshikaki" nocase ascii wide

    condition:
        any of them
}