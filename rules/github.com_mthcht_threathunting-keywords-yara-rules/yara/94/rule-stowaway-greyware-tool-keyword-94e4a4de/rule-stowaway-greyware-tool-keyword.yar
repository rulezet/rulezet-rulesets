rule rule_stowaway_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_stowaway_greyware_tool_keyword = "/linux_x64_admin"
                        $string2_stowaway_greyware_tool_keyword = "/linux_x64_agent"
                        $string3_stowaway_greyware_tool_keyword = "/linux_x86_admin"
                        $string4_stowaway_greyware_tool_keyword = "/linux_x86_agent"

    condition:
        any of them
}