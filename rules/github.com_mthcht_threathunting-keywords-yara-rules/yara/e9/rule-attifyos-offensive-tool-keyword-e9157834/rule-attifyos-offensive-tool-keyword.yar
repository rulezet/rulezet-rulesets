rule rule_attifyos_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'attifyos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attifyos"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_attifyos_offensive_tool_keyword = "AttifyOS" nocase ascii wide

    condition:
        any of them
}