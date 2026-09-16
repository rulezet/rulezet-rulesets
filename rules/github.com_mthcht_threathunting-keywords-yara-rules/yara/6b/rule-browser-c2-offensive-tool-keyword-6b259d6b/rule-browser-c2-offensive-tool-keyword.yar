rule rule_Browser_C2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browser-C2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-C2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Browser_C2_offensive_tool_keyword = "/Browser-C2" nocase ascii wide
                        $string2_Browser_C2_offensive_tool_keyword = /Browser\-C2\.git/ nocase ascii wide
                        $string3_Browser_C2_offensive_tool_keyword = /Browser\-C2\-master\.zip/ nocase ascii wide

    condition:
        any of them
}