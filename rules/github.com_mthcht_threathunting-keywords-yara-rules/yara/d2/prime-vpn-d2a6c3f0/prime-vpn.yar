rule Prime_VPN
{
    meta:
        description = "Detection patterns for the tool 'Prime VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Prime VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "akkbkhnikoeojlhiiomohpdnkhbkhieh" nocase ascii wide

    condition:
        any of them
}