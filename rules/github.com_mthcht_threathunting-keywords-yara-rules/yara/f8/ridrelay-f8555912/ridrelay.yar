rule ridrelay
{
    meta:
        description = "Detection patterns for the tool 'ridrelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ridrelay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "ridrelay" nocase ascii wide

    condition:
        any of them
}