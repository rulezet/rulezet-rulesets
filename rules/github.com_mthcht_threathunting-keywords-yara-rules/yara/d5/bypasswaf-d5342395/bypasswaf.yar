rule bypasswaf
{
    meta:
        description = "Detection patterns for the tool 'bypasswaf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypasswaf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /bypasswaf\.jar/ nocase ascii wide
                        $string2 = /bypasswaf\.py/ nocase ascii wide
                        $string3 = "codewatchorg/bypasswaf" nocase ascii wide

    condition:
        any of them
}