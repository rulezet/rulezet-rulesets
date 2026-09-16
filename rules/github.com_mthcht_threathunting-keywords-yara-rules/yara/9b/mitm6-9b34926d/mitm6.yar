rule mitm6
{
    meta:
        description = "Detection patterns for the tool 'mitm6' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitm6"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "mitm6 -d "
                        $string2 = /mitm6\.py/ nocase ascii wide

    condition:
        any of them
}