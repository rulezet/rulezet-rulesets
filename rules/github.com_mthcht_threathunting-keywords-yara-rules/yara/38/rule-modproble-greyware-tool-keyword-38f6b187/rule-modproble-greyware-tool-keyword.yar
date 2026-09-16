rule rule_modproble_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'modproble' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "modproble"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_modproble_greyware_tool_keyword = "modprobe -r" nocase ascii wide
                        $string2_modproble_greyware_tool_keyword = "modprobe --remove" nocase ascii wide
                        $string3_modproble_greyware_tool_keyword = "modprobe rmmod -r" nocase ascii wide

    condition:
        any of them
}