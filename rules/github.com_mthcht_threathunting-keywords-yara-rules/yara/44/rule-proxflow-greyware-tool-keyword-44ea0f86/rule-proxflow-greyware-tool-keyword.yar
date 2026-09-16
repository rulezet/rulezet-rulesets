rule rule_ProxFlow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ProxFlow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxFlow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ProxFlow_greyware_tool_keyword = "aakchaleigkohafkfjfjbblobjifikek" nocase ascii wide

    condition:
        any of them
}