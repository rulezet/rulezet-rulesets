rule rule_SMBetray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMBetray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBetray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMBetray_offensive_tool_keyword = "SMBetray" nocase ascii wide

    condition:
        any of them
}