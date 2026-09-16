rule rule_uVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'uVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "uVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_uVPN_greyware_tool_keyword = "lejgfmmlngaigdmmikblappdafcmkndb" nocase ascii wide

    condition:
        any of them
}