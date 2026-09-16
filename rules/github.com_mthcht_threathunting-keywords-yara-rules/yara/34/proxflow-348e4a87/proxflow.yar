rule ProxFlow
{
    meta:
        description = "Detection patterns for the tool 'ProxFlow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxFlow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "aakchaleigkohafkfjfjbblobjifikek" nocase ascii wide

    condition:
        any of them
}