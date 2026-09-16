rule SharpPrintNightmare
{
    meta:
        description = "Detection patterns for the tool 'SharpPrintNightmare' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPrintNightmare"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "SharpPrintNightmare" nocase ascii wide

    condition:
        any of them
}