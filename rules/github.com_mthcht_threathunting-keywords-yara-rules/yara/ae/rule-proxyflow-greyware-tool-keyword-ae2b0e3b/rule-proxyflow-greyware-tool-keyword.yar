rule rule_ProxyFlow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ProxyFlow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxyFlow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ProxyFlow_greyware_tool_keyword = "llbhddikeonkpbhpncnhialfbpnilcnc" nocase ascii wide

    condition:
        any of them
}