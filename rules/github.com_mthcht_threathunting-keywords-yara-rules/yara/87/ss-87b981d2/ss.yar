rule ss
{
    meta:
        description = "Detection patterns for the tool 'ss' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ss"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ss -lntp" nocase ascii wide

    condition:
        any of them
}