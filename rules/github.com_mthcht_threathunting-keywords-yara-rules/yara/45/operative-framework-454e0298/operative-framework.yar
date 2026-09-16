rule Operative_Framework
{
    meta:
        description = "Detection patterns for the tool 'Operative Framework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Operative Framework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Operative Framework" nocase ascii wide

    condition:
        any of them
}