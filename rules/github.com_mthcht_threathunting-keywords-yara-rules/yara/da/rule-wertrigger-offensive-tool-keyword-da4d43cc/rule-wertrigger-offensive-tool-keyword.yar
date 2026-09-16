rule rule_WerTrigger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WerTrigger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WerTrigger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WerTrigger_offensive_tool_keyword = /\/WerTrigger\.git/ nocase ascii wide
                        $string2_WerTrigger_offensive_tool_keyword = /WerTrigger\.exe/ nocase ascii wide
                        $string3_WerTrigger_offensive_tool_keyword = "WerTrigger-master" nocase ascii wide

    condition:
        any of them
}