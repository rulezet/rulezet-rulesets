rule AdvancedRun
{
    meta:
        description = "Detection patterns for the tool 'AdvancedRun' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdvancedRun"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /AdvancedRun\.exe\s/ nocase ascii wide

    condition:
        any of them
}