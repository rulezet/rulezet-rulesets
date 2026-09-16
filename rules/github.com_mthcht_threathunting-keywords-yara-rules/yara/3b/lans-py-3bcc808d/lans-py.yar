rule LANs_py
{
    meta:
        description = "Detection patterns for the tool 'LANs.py' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LANs.py"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /LANs\.py/ nocase ascii wide

    condition:
        any of them
}