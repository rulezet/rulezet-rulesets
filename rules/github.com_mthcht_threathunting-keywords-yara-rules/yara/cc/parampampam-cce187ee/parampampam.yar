rule ParamPamPam
{
    meta:
        description = "Detection patterns for the tool 'ParamPamPam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ParamPamPam"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "ParamPamPam" nocase ascii wide

    condition:
        any of them
}