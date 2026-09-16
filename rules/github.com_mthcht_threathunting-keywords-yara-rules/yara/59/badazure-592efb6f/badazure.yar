rule badazure
{
    meta:
        description = "Detection patterns for the tool 'badazure' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badazure"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -Build -NoAttackPaths" nocase ascii wide
                        $string2 = /\/BadZure\.git/ nocase ascii wide
                        $string3 = "/BadZure/" nocase ascii wide
                        $string4 = /\\BadZure/ nocase ascii wide
                        $string5 = "BadZure-main" nocase ascii wide
                        $string6 = /\-Build\s\$RandomAttackPath/ nocase ascii wide
                        $string7 = "Invoke-BadZure" nocase ascii wide
                        $string8 = "mvelazc0/BadZure" nocase ascii wide
                        $string9 = "-RandomAttackPath -Token" nocase ascii wide

    condition:
        any of them
}