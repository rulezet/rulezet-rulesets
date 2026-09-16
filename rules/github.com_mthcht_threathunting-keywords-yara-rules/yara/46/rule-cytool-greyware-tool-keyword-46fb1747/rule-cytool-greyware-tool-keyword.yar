rule rule_cytool_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cytool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cytool"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_cytool_greyware_tool_keyword = /cytool\.exe\sevent_collection\sdisable/ nocase ascii wide
                        $string2_cytool_greyware_tool_keyword = /cytool\.exe\sprotect\sdisable/ nocase ascii wide
                        $string3_cytool_greyware_tool_keyword = /cytool\.exe\sruntime\sdisable/ nocase ascii wide
                        $string4_cytool_greyware_tool_keyword = /cytool\.exe\sstartup\sdisable/ nocase ascii wide

    condition:
        any of them
}