rule rapid7
{
    meta:
        description = "Detection patterns for the tool 'rapid7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rapid7"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "Rapid7" nocase ascii wide
                        $string2 = /test\.endpoint\.rapid7\.com/ nocase ascii wide

    condition:
        any of them
}