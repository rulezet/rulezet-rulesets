rule w3af
{
    meta:
        description = "Detection patterns for the tool 'w3af' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "w3af"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "w3af_gui" nocase ascii wide

    condition:
        any of them
}