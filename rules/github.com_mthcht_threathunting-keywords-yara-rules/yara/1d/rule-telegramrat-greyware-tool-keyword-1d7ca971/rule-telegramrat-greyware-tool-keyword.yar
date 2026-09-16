rule rule_TelegramRAT_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TelegramRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TelegramRAT"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_TelegramRAT_greyware_tool_keyword = /https\:\/\/api\.telegram\.org\/bot.{0,1000}\/sendMessage/ nocase ascii wide

    condition:
        any of them
}