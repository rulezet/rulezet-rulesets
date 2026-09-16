rule rule_rapid7_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rapid7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rapid7"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rapid7_greyware_tool_keyword = "Rapid7" nocase ascii wide
                        $string2_rapid7_greyware_tool_keyword = /test\.endpoint\.rapid7\.com/ nocase ascii wide

    condition:
        any of them
}