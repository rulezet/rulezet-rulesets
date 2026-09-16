rule rule_obfy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'obfy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "obfy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_obfy_offensive_tool_keyword = "/fritzone/obfy" nocase ascii wide
                        $string2_obfy_offensive_tool_keyword = /\\obfy\-1\.0\.zip/ nocase ascii wide

    condition:
        any of them
}