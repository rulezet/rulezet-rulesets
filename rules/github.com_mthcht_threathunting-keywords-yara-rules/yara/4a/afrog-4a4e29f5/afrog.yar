rule afrog
{
    meta:
        description = "Detection patterns for the tool 'afrog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "afrog"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/afrog-pocs/" nocase ascii wide
                        $string2 = "afrog -" nocase ascii wide

    condition:
        any of them
}