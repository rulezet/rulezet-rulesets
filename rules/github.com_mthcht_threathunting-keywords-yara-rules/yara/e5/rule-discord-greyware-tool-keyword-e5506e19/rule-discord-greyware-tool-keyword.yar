rule rule_discord_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'discord' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "discord"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.bat/ nocase ascii wide
                        $string2_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.exe/ nocase ascii wide
                        $string3_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.hta/ nocase ascii wide
                        $string4_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.iso/ nocase ascii wide
                        $string5_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.jar/ nocase ascii wide
                        $string6_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.msi/ nocase ascii wide
                        $string7_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.py/ nocase ascii wide
                        $string8_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.vbs/ nocase ascii wide
                        $string9_discord_greyware_tool_keyword = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}