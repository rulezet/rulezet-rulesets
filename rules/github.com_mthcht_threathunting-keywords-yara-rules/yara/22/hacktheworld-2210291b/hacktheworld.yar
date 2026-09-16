rule HackTheWorld
{
    meta:
        description = "Detection patterns for the tool 'HackTheWorld' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HackTheWorld"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "HackTheWorld" nocase ascii wide
                        $string2 = "stormshadow07" nocase ascii wide

    condition:
        any of them
}