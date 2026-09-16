rule rule_Drupwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Drupwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Drupwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Drupwn_offensive_tool_keyword = "/Drupwn"

    condition:
        any of them
}