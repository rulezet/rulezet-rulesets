rule rshijack
{
    meta:
        description = "Detection patterns for the tool 'rshijack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rshijack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "rshijack" nocase ascii wide

    condition:
        any of them
}