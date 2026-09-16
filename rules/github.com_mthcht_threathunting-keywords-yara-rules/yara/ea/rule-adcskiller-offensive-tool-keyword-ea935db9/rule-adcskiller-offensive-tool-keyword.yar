rule rule_ADCSKiller_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADCSKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADCSKiller_offensive_tool_keyword = "/ADCSKiller" nocase ascii wide
                        $string2_ADCSKiller_offensive_tool_keyword = /adcskiller\.py/ nocase ascii wide
                        $string3_ADCSKiller_offensive_tool_keyword = "ly4k/Certipy" nocase ascii wide
                        $string4_ADCSKiller_offensive_tool_keyword = "p0dalirius/Coercer" nocase ascii wide

    condition:
        any of them
}