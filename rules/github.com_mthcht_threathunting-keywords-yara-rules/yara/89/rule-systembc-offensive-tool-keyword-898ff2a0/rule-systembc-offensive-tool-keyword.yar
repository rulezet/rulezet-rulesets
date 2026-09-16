rule rule_SystemBC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SystemBC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SystemBC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SystemBC_offensive_tool_keyword = /\/tmp\/socks5\.sh/

    condition:
        any of them
}