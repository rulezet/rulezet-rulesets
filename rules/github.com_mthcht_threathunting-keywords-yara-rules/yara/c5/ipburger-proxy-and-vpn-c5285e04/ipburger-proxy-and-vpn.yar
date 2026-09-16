rule IPBurger_Proxy__and__VPN
{
    meta:
        description = "Detection patterns for the tool 'IPBurger Proxy & VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IPBurger Proxy & VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "kchocjcihdgkoplngjemhpplmmloanja" nocase ascii wide

    condition:
        any of them
}