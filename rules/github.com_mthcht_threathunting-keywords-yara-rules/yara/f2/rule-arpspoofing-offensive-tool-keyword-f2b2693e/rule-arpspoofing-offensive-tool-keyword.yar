rule rule_arpspoofing_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'arpspoofing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "arpspoofing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_arpspoofing_offensive_tool_keyword = "/luijait/arpspoofing" nocase ascii wide
                        $string2_arpspoofing_offensive_tool_keyword = /arpspoofing\.py\s/ nocase ascii wide

    condition:
        any of them
}