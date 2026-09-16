rule archerysec
{
    meta:
        description = "Detection patterns for the tool 'archerysec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "archerysec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "archerysec" nocase ascii wide

    condition:
        any of them
}