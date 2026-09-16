rule AggressorScripts_1
{
    meta:
        description = "Detection patterns for the tool 'AggressorScripts-1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AggressorScripts-1"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "AggressorScripts" nocase ascii wide
                        $string2 = /Persist\.cna/ nocase ascii wide

    condition:
        any of them
}