rule rule_discord_c2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'discord-c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "discord-c2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_discord_c2_offensive_tool_keyword = "// Discord C2" nocase ascii wide
                        $string2_discord_c2_offensive_tool_keyword = "// William Moody" nocase ascii wide
                        $string3_discord_c2_offensive_tool_keyword = /\/discord\-c2\.git/ nocase ascii wide
                        $string4_discord_c2_offensive_tool_keyword = /\\discord\-c2\\/ nocase ascii wide
                        $string5_discord_c2_offensive_tool_keyword = "bmdyy/discord-c2" nocase ascii wide
                        $string6_discord_c2_offensive_tool_keyword = /discordgo\.New\(\\"Bot\s\.\.\.\\"\)/ nocase ascii wide

    condition:
        any of them
}