rule Drupwn
{
    meta:
        description = "Detection patterns for the tool 'Drupwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Drupwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Drupwn"

    condition:
        any of them
}