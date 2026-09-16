rule charles_proxy
{
    meta:
        description = "Detection patterns for the tool 'charles-proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "charles-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "charles-proxy" nocase ascii wide

    condition:
        any of them
}