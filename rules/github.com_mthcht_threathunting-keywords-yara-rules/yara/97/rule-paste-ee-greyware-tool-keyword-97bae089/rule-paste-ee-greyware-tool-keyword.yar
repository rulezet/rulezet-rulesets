rule rule_paste_ee_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'paste.ee' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "paste.ee"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_paste_ee_greyware_tool_keyword = /paste\.ee\/d\// nocase ascii wide
                        $string2_paste_ee_greyware_tool_keyword = /paste\.ee\/paste/ nocase ascii wide

    condition:
        any of them
}