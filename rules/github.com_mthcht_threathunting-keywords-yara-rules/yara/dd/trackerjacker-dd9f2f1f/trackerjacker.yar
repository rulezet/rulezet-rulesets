rule trackerjacker
{
    meta:
        description = "Detection patterns for the tool 'trackerjacker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "trackerjacker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/trackerjacker"

    condition:
        any of them
}