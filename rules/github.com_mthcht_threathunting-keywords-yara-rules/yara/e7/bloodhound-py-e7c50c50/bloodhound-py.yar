rule BloodHound_py
{
    meta:
        description = "Detection patterns for the tool 'BloodHound.py' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BloodHound.py"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /bloodhound\.py\s/ nocase ascii wide

    condition:
        any of them
}