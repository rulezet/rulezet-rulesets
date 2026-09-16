rule Cowpatty
{
    meta:
        description = "Detection patterns for the tool 'Cowpatty' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cowpatty"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Cowpatty" nocase ascii wide

    condition:
        any of them
}