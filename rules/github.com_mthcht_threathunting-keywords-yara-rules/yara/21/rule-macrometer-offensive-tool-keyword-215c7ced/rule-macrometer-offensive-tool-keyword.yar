rule rule_MacroMeter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MacroMeter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MacroMeter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MacroMeter_offensive_tool_keyword = "/MacroMeter" nocase ascii wide
                        $string2_MacroMeter_offensive_tool_keyword = /\\tricky\.ps1/ nocase ascii wide

    condition:
        any of them
}