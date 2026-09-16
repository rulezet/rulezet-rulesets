rule gtfobins
{
    meta:
        description = "Detection patterns for the tool 'gtfobins' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gtfobins"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "gtfobins"

    condition:
        any of them
}