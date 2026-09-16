rule rule_DumpsterFire_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DumpsterFire' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpsterFire"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DumpsterFire_offensive_tool_keyword = "/DumpsterFire/" nocase ascii wide

    condition:
        any of them
}