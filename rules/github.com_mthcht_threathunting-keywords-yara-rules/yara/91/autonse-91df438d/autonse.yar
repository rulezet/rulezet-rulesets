rule autonse
{
    meta:
        description = "Detection patterns for the tool 'autonse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autonse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "AutoNSE" nocase ascii wide

    condition:
        any of them
}