rule wpaf
{
    meta:
        description = "Detection patterns for the tool 'wpaf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wpaf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/wpaf\/finder\.py/
                        $string2 = "kancotdiq/wpaf" nocase ascii wide

    condition:
        any of them
}