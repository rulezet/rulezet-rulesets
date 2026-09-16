rule anydesk
{
    meta:
        description = "Detection patterns for the tool 'anydesk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anydesk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /discordapp\.com\/attachments\/.{0,1000}\/AnyDesk\.exe/ nocase ascii wide

    condition:
        any of them
}