rule patator
{
    meta:
        description = "Detection patterns for the tool 'patator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "patator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "patator" nocase ascii wide

    condition:
        any of them
}