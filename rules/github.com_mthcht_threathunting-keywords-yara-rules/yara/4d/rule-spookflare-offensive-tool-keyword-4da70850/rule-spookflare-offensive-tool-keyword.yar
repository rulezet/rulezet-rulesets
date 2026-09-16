rule rule_SpookFlare_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpookFlare' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpookFlare"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SpookFlare_offensive_tool_keyword = "SpookFlare" nocase ascii wide

    condition:
        any of them
}