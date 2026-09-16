rule rule_http_server_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'http.server' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "http.server"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_http_server_greyware_tool_keyword = /python\s\-m\shttp\.server/ nocase ascii wide
                        $string2_http_server_greyware_tool_keyword = /python3\s\-m\shttp\.server/ nocase ascii wide

    condition:
        any of them
}