rule Jormungandr
{
    meta:
        description = "Detection patterns for the tool 'Jormungandr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jormungandr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Jormungandr\.git/ nocase ascii wide
                        $string2 = /\\\\\?\?\\\\Jormungandr/ nocase ascii wide
                        $string3 = /COFFLdr\.cpp/ nocase ascii wide
                        $string4 = /COFFLdr\.exe/ nocase ascii wide
                        $string5 = "Idov31/Jormungandr" nocase ascii wide
                        $string6 = /Jormungandr\.cpp/ nocase ascii wide
                        $string7 = /Jormungandr\.exe/ nocase ascii wide
                        $string8 = "Jormungandr-master" nocase ascii wide

    condition:
        any of them
}