rule rule_ZenMate_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ZenMate VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ZenMate VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ZenMate_VPN_greyware_tool_keyword = "fdcgdnkidjaadafnichfpabhfomcebme" nocase ascii wide

    condition:
        any of them
}