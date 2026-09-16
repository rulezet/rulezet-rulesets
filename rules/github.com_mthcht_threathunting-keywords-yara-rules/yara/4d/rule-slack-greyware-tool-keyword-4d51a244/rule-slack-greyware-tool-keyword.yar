rule rule_slack_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'slack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "slack"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_slack_greyware_tool_keyword = /https\:\/\/slack\.com\/api\/channels\.create/ nocase ascii wide

    condition:
        any of them
}