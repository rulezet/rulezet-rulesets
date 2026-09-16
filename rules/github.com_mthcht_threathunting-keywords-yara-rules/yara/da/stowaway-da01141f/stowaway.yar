rule stowaway
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "/linux_x64_admin"
                        $string2 = "/linux_x64_agent"
                        $string3 = "/linux_x86_admin"
                        $string4 = "/linux_x86_agent"

    condition:
        any of them
}