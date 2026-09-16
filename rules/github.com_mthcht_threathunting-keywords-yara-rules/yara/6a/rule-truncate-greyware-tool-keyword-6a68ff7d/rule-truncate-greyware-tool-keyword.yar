rule rule_truncate_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'truncate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "truncate"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_truncate_greyware_tool_keyword = "truncate -s 0 /var/log/messages"
                        $string2_truncate_greyware_tool_keyword = "truncate --size=0 /var/log/security"

    condition:
        any of them
}