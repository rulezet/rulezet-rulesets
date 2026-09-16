rule rule_Thunder_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Thunder Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Thunder Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Thunder_Proxy_greyware_tool_keyword = "knmmpciebaoojcpjjoeonlcjacjopcpf" nocase ascii wide

    condition:
        any of them
}