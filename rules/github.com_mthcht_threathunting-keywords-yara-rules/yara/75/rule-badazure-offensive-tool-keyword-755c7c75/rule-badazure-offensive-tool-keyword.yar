rule rule_badazure_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'badazure' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badazure"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_badazure_offensive_tool_keyword = " -Build -NoAttackPaths" nocase ascii wide
                        $string2_badazure_offensive_tool_keyword = /\/BadZure\.git/ nocase ascii wide
                        $string3_badazure_offensive_tool_keyword = "/BadZure/" nocase ascii wide
                        $string4_badazure_offensive_tool_keyword = /\\BadZure/ nocase ascii wide
                        $string5_badazure_offensive_tool_keyword = "BadZure-main" nocase ascii wide
                        $string6_badazure_offensive_tool_keyword = /\-Build\s\$RandomAttackPath/ nocase ascii wide
                        $string7_badazure_offensive_tool_keyword = "Invoke-BadZure" nocase ascii wide
                        $string8_badazure_offensive_tool_keyword = "mvelazc0/BadZure" nocase ascii wide
                        $string9_badazure_offensive_tool_keyword = "-RandomAttackPath -Token" nocase ascii wide

    condition:
        any of them
}