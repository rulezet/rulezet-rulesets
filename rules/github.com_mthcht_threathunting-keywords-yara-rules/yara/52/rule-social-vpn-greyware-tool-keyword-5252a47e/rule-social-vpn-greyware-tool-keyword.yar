rule rule_Social_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Social VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Social VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Social_VPN_greyware_tool_keyword = "igahhbkcppaollcjeaaoapkijbnphfhb" nocase ascii wide

    condition:
        any of them
}