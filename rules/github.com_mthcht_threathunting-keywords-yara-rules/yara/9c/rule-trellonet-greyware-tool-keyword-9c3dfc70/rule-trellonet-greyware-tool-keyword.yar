rule rule_Trellonet_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Trellonet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Trellonet"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Trellonet_greyware_tool_keyword = "njpmifchgidinihmijhcfpbdmglecdlb" nocase ascii wide

    condition:
        any of them
}