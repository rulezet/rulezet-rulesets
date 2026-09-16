rule nping
{
    meta:
        description = "Detection patterns for the tool 'nping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nping"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "nping -" nocase ascii wide

    condition:
        any of them
}