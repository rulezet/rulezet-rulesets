rule rule_TelegramRAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TelegramRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TelegramRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TelegramRAT_offensive_tool_keyword = /\/TelegramRAT\.git/ nocase ascii wide
                        $string2_TelegramRAT_offensive_tool_keyword = /https\:\/\/t\.me\/BotFather/ nocase ascii wide
                        $string3_TelegramRAT_offensive_tool_keyword = /https\:\/\/t\.me\/machine1337/ nocase ascii wide
                        $string4_TelegramRAT_offensive_tool_keyword = "machine1337/TelegramRAT" nocase ascii wide
                        $string5_TelegramRAT_offensive_tool_keyword = "TelegramRAT-main" nocase ascii wide

    condition:
        any of them
}