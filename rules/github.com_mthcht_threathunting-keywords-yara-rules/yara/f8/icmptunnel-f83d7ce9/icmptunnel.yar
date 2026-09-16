rule icmptunnel
{
    meta:
        description = "Detection patterns for the tool 'icmptunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icmptunnel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "icmptunnel" nocase ascii wide

    condition:
        any of them
}