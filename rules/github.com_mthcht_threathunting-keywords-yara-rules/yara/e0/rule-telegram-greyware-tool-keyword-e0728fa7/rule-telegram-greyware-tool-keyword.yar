rule rule_telegram_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'telegram' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telegram"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_telegram_greyware_tool_keyword = /\\AppData\\Roaming\\Telegram\sDesktop\\tdata/ nocase ascii wide
                        $string2_telegram_greyware_tool_keyword = /api\.telegram\.org/ nocase ascii wide

    condition:
        any of them
}