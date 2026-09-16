rule Thunder_Proxy
{
    meta:
        description = "Detection patterns for the tool 'Thunder Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Thunder Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "knmmpciebaoojcpjjoeonlcjacjopcpf" nocase ascii wide

    condition:
        any of them
}