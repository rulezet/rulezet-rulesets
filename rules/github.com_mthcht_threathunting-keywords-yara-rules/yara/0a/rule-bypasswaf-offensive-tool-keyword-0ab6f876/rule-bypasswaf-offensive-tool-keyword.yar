rule rule_bypasswaf_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bypasswaf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypasswaf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bypasswaf_offensive_tool_keyword = /bypasswaf\.jar/ nocase ascii wide
                        $string2_bypasswaf_offensive_tool_keyword = /bypasswaf\.py/ nocase ascii wide
                        $string3_bypasswaf_offensive_tool_keyword = "codewatchorg/bypasswaf" nocase ascii wide

    condition:
        any of them
}