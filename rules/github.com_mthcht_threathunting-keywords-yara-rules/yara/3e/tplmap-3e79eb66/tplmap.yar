rule tplmap
{
    meta:
        description = "Detection patterns for the tool 'tplmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tplmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "tplmap" nocase ascii wide

    condition:
        any of them
}