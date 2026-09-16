rule Akira
{
    meta:
        description = "Detection patterns for the tool 'Akira' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Akira"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " :Failed to make full encrypt" nocase ascii wide
                        $string2 = "Paste this link - https://akira" nocase ascii wide

    condition:
        any of them
}