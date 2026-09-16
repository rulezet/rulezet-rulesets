rule rule_auditd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'auditd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "auditd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_auditd_greyware_tool_keyword = "auditctl -e 0"
                        $string2_auditd_greyware_tool_keyword = "auditctl -e0"
                        $string3_auditd_greyware_tool_keyword = "systemctl disable auditd"

    condition:
        any of them
}