rule net_creds
{
    meta:
        description = "Detection patterns for the tool 'net-creds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "net-creds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "DanMcInerney/net-creds" nocase ascii wide

    condition:
        any of them
}