rule rule__1secmail_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '1secmail.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1secmail.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__1secmail_com_greyware_tool_keyword = /www\.1secmail\.com\/api\/v1\/\?action\=/ nocase ascii wide

    condition:
        any of them
}