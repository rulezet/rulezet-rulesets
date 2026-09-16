rule TelegramRAT
{
    meta:
        description = "Detection patterns for the tool 'TelegramRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TelegramRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/TelegramRAT\.git/ nocase ascii wide
                        $string2 = /https\:\/\/t\.me\/BotFather/ nocase ascii wide
                        $string3 = /https\:\/\/t\.me\/machine1337/ nocase ascii wide
                        $string4 = "machine1337/TelegramRAT" nocase ascii wide
                        $string5 = "TelegramRAT-main" nocase ascii wide

    condition:
        any of them
}