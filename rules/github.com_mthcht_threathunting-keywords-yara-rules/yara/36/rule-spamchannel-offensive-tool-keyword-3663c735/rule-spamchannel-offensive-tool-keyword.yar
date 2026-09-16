rule rule_SpamChannel_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpamChannel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpamChannel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SpamChannel_offensive_tool_keyword = /\/SpamChannel\.git/ nocase ascii wide
                        $string2_SpamChannel_offensive_tool_keyword = "byt3bl33d3r/SpamChannel" nocase ascii wide
                        $string3_SpamChannel_offensive_tool_keyword = /SpamChannel\-main\.zip/ nocase ascii wide

    condition:
        any of them
}