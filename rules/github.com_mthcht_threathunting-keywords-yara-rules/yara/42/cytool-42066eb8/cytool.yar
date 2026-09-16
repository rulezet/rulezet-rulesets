rule cytool
{
    meta:
        description = "Detection patterns for the tool 'cytool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cytool"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cytool\.exe\sevent_collection\sdisable/ nocase ascii wide
                        $string2 = /cytool\.exe\sprotect\sdisable/ nocase ascii wide
                        $string3 = /cytool\.exe\sruntime\sdisable/ nocase ascii wide
                        $string4 = /cytool\.exe\sstartup\sdisable/ nocase ascii wide

    condition:
        any of them
}