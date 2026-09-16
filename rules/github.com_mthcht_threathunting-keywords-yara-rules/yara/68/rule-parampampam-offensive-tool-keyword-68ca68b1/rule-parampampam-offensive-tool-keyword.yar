rule rule_ParamPamPam_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ParamPamPam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ParamPamPam"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ParamPamPam_offensive_tool_keyword = "ParamPamPam" nocase ascii wide

    condition:
        any of them
}