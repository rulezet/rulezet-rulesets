rule CrossLinked
{
    meta:
        description = "Detection patterns for the tool 'CrossLinked' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CrossLinked"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "CrossLinked" nocase ascii wide

    condition:
        any of them
}