rule rule_dnscmd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnscmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscmd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dnscmd_greyware_tool_keyword = /dnscmd\s\.\s\/enumrecords\s\/zone\s/ nocase ascii wide
                        $string2_dnscmd_greyware_tool_keyword = /dnscmd\s\.\s\/enumzones/ nocase ascii wide

    condition:
        any of them
}