rule rule_Proxy_SwitchyOmega_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Proxy SwitchyOmega' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxy SwitchyOmega"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Proxy_SwitchyOmega_greyware_tool_keyword = "padekgcemlokbadohgkifijomclgjgif" nocase ascii wide

    condition:
        any of them
}