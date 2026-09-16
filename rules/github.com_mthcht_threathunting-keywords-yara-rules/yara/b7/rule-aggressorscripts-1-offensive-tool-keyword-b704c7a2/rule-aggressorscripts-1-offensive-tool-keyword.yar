rule rule_AggressorScripts_1_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AggressorScripts-1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AggressorScripts-1"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AggressorScripts_1_offensive_tool_keyword = "AggressorScripts" nocase ascii wide
                        $string2_AggressorScripts_1_offensive_tool_keyword = /Persist\.cna/ nocase ascii wide

    condition:
        any of them
}