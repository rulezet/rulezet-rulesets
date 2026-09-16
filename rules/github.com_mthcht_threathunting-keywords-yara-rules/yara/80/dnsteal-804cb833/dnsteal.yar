rule dnsteal
{
    meta:
        description = "Detection patterns for the tool 'dnsteal' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsteal"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/dnsteal" nocase ascii wide
                        $string2 = /dnsteal\.git/ nocase ascii wide
                        $string3 = /dnsteal\.py/ nocase ascii wide
                        $string4 = "dnsteal-master" nocase ascii wide

    condition:
        any of them
}