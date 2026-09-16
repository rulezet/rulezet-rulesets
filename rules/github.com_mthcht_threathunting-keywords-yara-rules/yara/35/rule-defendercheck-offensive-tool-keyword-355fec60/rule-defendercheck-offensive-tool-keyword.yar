rule rule_DefenderCheck_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DefenderCheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DefenderCheck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DefenderCheck_offensive_tool_keyword = "DefenderCheck" nocase ascii wide
                        $string2_DefenderCheck_offensive_tool_keyword = /DefenderCheck\.exe/ nocase ascii wide
                        $string3_DefenderCheck_offensive_tool_keyword = "matterpreter/DefenderCheck" nocase ascii wide

    condition:
        any of them
}