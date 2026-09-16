rule rule_pyLAPS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pyLAPS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyLAPS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pyLAPS_offensive_tool_keyword = /\spyLAPS\.py/
                        $string2_pyLAPS_offensive_tool_keyword = /\/pyLAPS\.git/
                        $string3_pyLAPS_offensive_tool_keyword = /\/pyLAPS\.py/
                        $string4_pyLAPS_offensive_tool_keyword = "p0dalirius/pyLAPS"
                        $string5_pyLAPS_offensive_tool_keyword = "pyLAPS-main"

    condition:
        any of them
}