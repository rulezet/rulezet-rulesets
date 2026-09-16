rule GatherContacts
{
    meta:
        description = "Detection patterns for the tool 'GatherContacts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GatherContacts"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "clr2of8/GatherContacts" nocase ascii wide

    condition:
        any of them
}