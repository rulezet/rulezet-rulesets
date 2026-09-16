rule rule_unshadow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unshadow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unshadow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_unshadow_greyware_tool_keyword = "unshadow passwd shadow > "

    condition:
        any of them
}