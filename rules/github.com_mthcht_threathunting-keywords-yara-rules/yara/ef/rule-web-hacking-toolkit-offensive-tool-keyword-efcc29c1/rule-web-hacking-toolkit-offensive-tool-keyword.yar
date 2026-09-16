rule rule_web_hacking_toolkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'web-hacking-toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "web-hacking-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_web_hacking_toolkit_offensive_tool_keyword = " web-hacking-toolkit " nocase ascii wide
                        $string2_web_hacking_toolkit_offensive_tool_keyword = "/web-hacking-toolkit" nocase ascii wide
                        $string3_web_hacking_toolkit_offensive_tool_keyword = /web\-hacking\-toolkit\.git/ nocase ascii wide

    condition:
        any of them
}