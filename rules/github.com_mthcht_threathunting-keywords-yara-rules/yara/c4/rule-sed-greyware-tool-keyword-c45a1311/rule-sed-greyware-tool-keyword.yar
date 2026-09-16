rule rule_sed_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sed' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sed"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sed_greyware_tool_keyword = "sed 's/#PermitRootLogin prohibit-password/PermitRootLogin Yes' /etc/ssh/sshd_config"

    condition:
        any of them
}