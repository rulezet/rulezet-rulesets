rule SpamChannel
{
    meta:
        description = "Detection patterns for the tool 'SpamChannel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpamChannel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SpamChannel\.git/ nocase ascii wide
                        $string2 = "byt3bl33d3r/SpamChannel" nocase ascii wide
                        $string3 = /SpamChannel\-main\.zip/ nocase ascii wide

    condition:
        any of them
}