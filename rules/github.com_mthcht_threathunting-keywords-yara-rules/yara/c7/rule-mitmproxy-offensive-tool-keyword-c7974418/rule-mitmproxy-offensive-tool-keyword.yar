rule rule_mitmproxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mitmproxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmproxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mitmproxy_offensive_tool_keyword = "6870cfc153e4d1478d4a3907036f32b7ebb1183810375475a436debb584fd8d3" nocase ascii wide
                        $string2_mitmproxy_offensive_tool_keyword = "mitmdump"
                        $string3_mitmproxy_offensive_tool_keyword = "mitmproxy"
                        $string4_mitmproxy_offensive_tool_keyword = "mitmweb"

    condition:
        any of them
}