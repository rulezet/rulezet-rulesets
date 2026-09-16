rule mitmproxy
{
    meta:
        description = "Detection patterns for the tool 'mitmproxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmproxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "6870cfc153e4d1478d4a3907036f32b7ebb1183810375475a436debb584fd8d3" nocase ascii wide
                        $string2 = "mitmdump"
                        $string3 = "mitmproxy"
                        $string4 = "mitmweb"

    condition:
        any of them
}