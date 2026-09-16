rule rule_BloodHound_py_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BloodHound.py' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BloodHound.py"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BloodHound_py_offensive_tool_keyword = /bloodhound\.py\s/ nocase ascii wide

    condition:
        any of them
}