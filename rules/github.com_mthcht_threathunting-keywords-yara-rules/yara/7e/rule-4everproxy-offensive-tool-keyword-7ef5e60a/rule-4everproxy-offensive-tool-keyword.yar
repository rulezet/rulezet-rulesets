rule rule__4everproxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '4everproxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "4everproxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__4everproxy_offensive_tool_keyword = /vh\.4everproxy\.com\/secure\// nocase ascii wide
                        $string2__4everproxy_offensive_tool_keyword = /www\.4everproxy\.com\/tor\-proxy/ nocase ascii wide

    condition:
        any of them
}