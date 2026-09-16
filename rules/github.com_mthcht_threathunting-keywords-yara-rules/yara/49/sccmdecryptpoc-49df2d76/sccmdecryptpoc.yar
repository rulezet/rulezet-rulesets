rule sccmdecryptpoc
{
    meta:
        description = "Detection patterns for the tool 'sccmdecryptpoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sccmdecryptpoc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /sccmdecryptpoc\./ nocase ascii wide

    condition:
        any of them
}