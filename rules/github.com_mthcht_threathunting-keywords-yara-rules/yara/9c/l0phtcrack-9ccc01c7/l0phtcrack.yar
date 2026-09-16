rule L0phtCrack
{
    meta:
        description = "Detection patterns for the tool 'L0phtCrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "L0phtCrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "L0phtCrack" nocase ascii wide

    condition:
        any of them
}