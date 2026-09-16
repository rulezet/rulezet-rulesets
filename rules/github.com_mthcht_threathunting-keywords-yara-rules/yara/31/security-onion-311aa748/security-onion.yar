rule security_onion
{
    meta:
        description = "Detection patterns for the tool 'security-onion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "security-onion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "security-onion" nocase ascii wide

    condition:
        any of them
}