rule discord
{
    meta:
        description = "Detection patterns for the tool 'discord' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "discord"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.bat/ nocase ascii wide
                        $string2 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.exe/ nocase ascii wide
                        $string3 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.hta/ nocase ascii wide
                        $string4 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.iso/ nocase ascii wide
                        $string5 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.jar/ nocase ascii wide
                        $string6 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.msi/ nocase ascii wide
                        $string7 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.py/ nocase ascii wide
                        $string8 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.vbs/ nocase ascii wide
                        $string9 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}