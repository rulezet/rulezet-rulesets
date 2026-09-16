rule Proxy_SwitchySharp
{
    meta:
        description = "Detection patterns for the tool 'Proxy SwitchySharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxy SwitchySharp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "dpplabbmogkhghncfbfdeeokoefdjegm" nocase ascii wide

    condition:
        any of them
}