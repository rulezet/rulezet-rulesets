rule diskshadow
{
    meta:
        description = "Detection patterns for the tool 'diskshadow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "diskshadow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "diskshadow /s " nocase ascii wide
                        $string2 = "diskshadow list shadows all" nocase ascii wide
                        $string3 = "diskshadow -s " nocase ascii wide
                        $string4 = /diskshadow\.exe\s\/s\s/ nocase ascii wide
                        $string5 = /diskshadow\.exe\slist\sshadows\sall/ nocase ascii wide
                        $string6 = /diskshadow\.exe\s\-s\s/ nocase ascii wide
                        $string7 = /diskshadow\.exe\\"\s\/s\s/ nocase ascii wide
                        $string8 = /diskshadow\.exe\\"\slist\sshadows\sall/ nocase ascii wide
                        $string9 = /diskshadow\.exe\\"\s\-s\s/ nocase ascii wide

    condition:
        any of them
}