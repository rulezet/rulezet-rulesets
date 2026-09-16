rule unshadow
{
    meta:
        description = "Detection patterns for the tool 'unshadow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unshadow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "unshadow passwd shadow > "

    condition:
        any of them
}