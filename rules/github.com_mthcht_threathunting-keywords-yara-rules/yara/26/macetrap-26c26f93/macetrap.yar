rule macetrap
{
    meta:
        description = "Detection patterns for the tool 'macetrap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macetrap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /MaceTrap\.exe/ nocase ascii wide

    condition:
        any of them
}