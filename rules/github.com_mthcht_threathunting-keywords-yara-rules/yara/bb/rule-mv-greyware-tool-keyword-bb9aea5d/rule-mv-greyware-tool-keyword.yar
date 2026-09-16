rule rule_mv_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mv' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mv"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_mv_greyware_tool_keyword = "mv /var/log/"

    condition:
        any of them
}