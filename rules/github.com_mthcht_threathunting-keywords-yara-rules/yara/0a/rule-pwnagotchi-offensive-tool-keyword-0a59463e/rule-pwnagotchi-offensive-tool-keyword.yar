rule rule_pwnagotchi_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pwnagotchi' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwnagotchi"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pwnagotchi_offensive_tool_keyword = "pwnagotchi" nocase ascii wide

    condition:
        any of them
}