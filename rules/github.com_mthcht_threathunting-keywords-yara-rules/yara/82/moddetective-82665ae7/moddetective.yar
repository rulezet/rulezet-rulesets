rule modDetective
{
    meta:
        description = "Detection patterns for the tool 'modDetective' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "modDetective"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "modDetective" nocase ascii wide

    condition:
        any of them
}