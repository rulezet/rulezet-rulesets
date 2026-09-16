rule discord_c2
{
    meta:
        description = "Detection patterns for the tool 'discord-c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "discord-c2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "// Discord C2" nocase ascii wide
                        $string2 = "// William Moody" nocase ascii wide
                        $string3 = /\/discord\-c2\.git/ nocase ascii wide
                        $string4 = /\\discord\-c2\\/ nocase ascii wide
                        $string5 = "bmdyy/discord-c2" nocase ascii wide
                        $string6 = /discordgo\.New\(\\"Bot\s\.\.\.\\"\)/ nocase ascii wide

    condition:
        any of them
}