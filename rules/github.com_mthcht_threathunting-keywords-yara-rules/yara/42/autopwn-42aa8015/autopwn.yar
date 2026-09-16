rule autopwn
{
    meta:
        description = "Detection patterns for the tool 'autopwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autopwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "autopwn" nocase ascii wide

    condition:
        any of them
}