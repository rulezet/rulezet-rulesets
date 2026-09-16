rule catbox_moe
{
    meta:
        description = "Detection patterns for the tool 'catbox.moe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catbox.moe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/files\.catbox\.moe\// nocase ascii wide

    condition:
        any of them
}