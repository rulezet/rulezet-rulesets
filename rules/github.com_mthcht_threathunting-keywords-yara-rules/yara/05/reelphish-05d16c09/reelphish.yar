rule ReelPhish
{
    meta:
        description = "Detection patterns for the tool 'ReelPhish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReelPhish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "ReelPhish" nocase ascii wide

    condition:
        any of them
}