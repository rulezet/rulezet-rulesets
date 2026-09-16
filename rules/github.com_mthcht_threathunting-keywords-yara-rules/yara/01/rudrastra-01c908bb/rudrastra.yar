rule Rudrastra
{
    meta:
        description = "Detection patterns for the tool 'Rudrastra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rudrastra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Rudrastra\.git/ nocase ascii wide
                        $string2 = "aircrack-ng" nocase ascii wide
                        $string3 = /fake_ap\.py/ nocase ascii wide
                        $string4 = "install macchanger" nocase ascii wide
                        $string5 = "macchanger -r" nocase ascii wide
                        $string6 = /Rudrastra\-main\.zip/ nocase ascii wide
                        $string7 = "SxNade/Rudrastra" nocase ascii wide

    condition:
        any of them
}