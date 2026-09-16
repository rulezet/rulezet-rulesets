rule rule_afrog_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'afrog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "afrog"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_afrog_offensive_tool_keyword = "/afrog-pocs/" nocase ascii wide
                        $string2_afrog_offensive_tool_keyword = "afrog -" nocase ascii wide

    condition:
        any of them
}