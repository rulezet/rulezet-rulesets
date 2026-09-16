rule rule_VPNMatic_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPNMatic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPNMatic"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_VPNMatic_greyware_tool_keyword = "bkkgdjpomdnfemhhkalfkogckjdkcjkg" nocase ascii wide

    condition:
        any of them
}