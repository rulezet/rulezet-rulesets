rule EDR_Test
{
    meta:
        description = "Detection patterns for the tool 'EDR-Test' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDR-Test"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "TH3xACE/EDR-Test" nocase ascii wide

    condition:
        any of them
}