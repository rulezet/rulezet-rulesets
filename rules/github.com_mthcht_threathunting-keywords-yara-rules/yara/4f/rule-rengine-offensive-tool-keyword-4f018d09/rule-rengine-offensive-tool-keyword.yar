rule rule_rengine_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rengine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rengine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rengine_offensive_tool_keyword = "yogeshojha/rengine" nocase ascii wide

    condition:
        any of them
}