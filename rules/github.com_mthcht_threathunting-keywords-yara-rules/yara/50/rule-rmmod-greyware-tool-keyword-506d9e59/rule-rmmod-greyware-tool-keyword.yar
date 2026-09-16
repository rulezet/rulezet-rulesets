rule rule_rmmod_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rmmod' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmmod"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rmmod_greyware_tool_keyword = "rmmod -r" nocase ascii wide
                        $string2_rmmod_greyware_tool_keyword = "rmmod --remove" nocase ascii wide
                        $string3_rmmod_greyware_tool_keyword = "sudo rmmod -r"

    condition:
        any of them
}