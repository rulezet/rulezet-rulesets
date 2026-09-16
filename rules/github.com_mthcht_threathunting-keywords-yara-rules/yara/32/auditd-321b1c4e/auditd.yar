rule auditd
{
    meta:
        description = "Detection patterns for the tool 'auditd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "auditd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "auditctl -e 0"
                        $string2 = "auditctl -e0"
                        $string3 = "systemctl disable auditd"

    condition:
        any of them
}