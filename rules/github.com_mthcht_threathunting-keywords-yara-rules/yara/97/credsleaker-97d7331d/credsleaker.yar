rule CredsLeaker
{
    meta:
        description = "Detection patterns for the tool 'CredsLeaker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredsLeaker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "CredsLeaker" nocase ascii wide

    condition:
        any of them
}