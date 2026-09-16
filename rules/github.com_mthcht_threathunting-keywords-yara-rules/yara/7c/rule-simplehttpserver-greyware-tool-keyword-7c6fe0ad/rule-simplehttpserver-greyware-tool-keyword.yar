rule rule_simplehttpserver_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'simplehttpserver' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "simplehttpserver"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_simplehttpserver_greyware_tool_keyword = " -m SimpleHTTPServer " nocase ascii wide
                        $string2_simplehttpserver_greyware_tool_keyword = "import SimpleHTTPServer" nocase ascii wide
                        $string3_simplehttpserver_greyware_tool_keyword = "python -m SimpleHTTPServer" nocase ascii wide
                        $string4_simplehttpserver_greyware_tool_keyword = /SimpleHTTPServer\.SimpleHTTPRequestHandler/ nocase ascii wide

    condition:
        any of them
}