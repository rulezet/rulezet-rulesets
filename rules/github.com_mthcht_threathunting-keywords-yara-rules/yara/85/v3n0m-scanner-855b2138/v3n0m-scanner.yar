rule V3n0M_Scanner
{
    meta:
        description = "Detection patterns for the tool 'V3n0M-Scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "V3n0M-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "V3n0M-Scanner" nocase ascii wide

    condition:
        any of them
}