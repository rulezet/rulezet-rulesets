rule rule_catbox_moe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'catbox.moe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catbox.moe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_catbox_moe_greyware_tool_keyword = /https\:\/\/files\.catbox\.moe\// nocase ascii wide

    condition:
        any of them
}