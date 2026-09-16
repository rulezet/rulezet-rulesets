rule mv
{
    meta:
        description = "Detection patterns for the tool 'mv' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mv"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "mv /var/log/"

    condition:
        any of them
}