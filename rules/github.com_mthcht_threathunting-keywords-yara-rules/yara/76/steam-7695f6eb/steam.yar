rule steam
{
    meta:
        description = "Detection patterns for the tool 'steam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "steam"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/steamcommunity\.com\/profiles\// nocase ascii wide

    condition:
        any of them
}