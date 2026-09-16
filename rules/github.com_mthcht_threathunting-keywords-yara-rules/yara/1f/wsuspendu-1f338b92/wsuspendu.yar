rule WSUSpendu
{
    meta:
        description = "Detection patterns for the tool 'WSUSpendu' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSUSpendu"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "WSUSpendu" nocase ascii wide

    condition:
        any of them
}