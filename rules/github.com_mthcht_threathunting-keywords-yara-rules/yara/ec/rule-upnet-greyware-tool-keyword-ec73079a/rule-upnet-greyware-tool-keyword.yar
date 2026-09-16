rule rule_Upnet_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Upnet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Upnet"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Upnet_greyware_tool_keyword = "bniikohfmajhdcffljgfeiklcbgffppl" nocase ascii wide

    condition:
        any of them
}