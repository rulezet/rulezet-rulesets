rule Droopscan
{
    meta:
        description = "Detection patterns for the tool 'Droopscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Droopscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Droopscan" nocase ascii wide

    condition:
        any of them
}