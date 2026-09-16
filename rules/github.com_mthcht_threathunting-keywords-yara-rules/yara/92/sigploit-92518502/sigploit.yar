rule SigPloit
{
    meta:
        description = "Detection patterns for the tool 'SigPloit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SigPloit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "SigPloit" nocase ascii wide

    condition:
        any of them
}