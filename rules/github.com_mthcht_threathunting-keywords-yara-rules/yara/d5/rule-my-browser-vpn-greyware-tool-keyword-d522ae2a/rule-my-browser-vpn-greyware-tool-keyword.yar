rule rule_My_Browser_Vpn_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'My Browser Vpn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "My Browser Vpn"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_My_Browser_Vpn_greyware_tool_keyword = "ppajinakbfocjfnijggfndbdmjggcmde" nocase ascii wide

    condition:
        any of them
}