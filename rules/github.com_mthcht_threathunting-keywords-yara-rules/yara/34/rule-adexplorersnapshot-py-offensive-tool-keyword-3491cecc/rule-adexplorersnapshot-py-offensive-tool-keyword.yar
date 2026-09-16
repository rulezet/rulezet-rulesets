rule rule_ADExplorerSnapshot_py_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADExplorerSnapshot.py' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADExplorerSnapshot.py"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADExplorerSnapshot_py_offensive_tool_keyword = /ADExplorerSnapshot\.py/ nocase ascii wide
                        $string2_ADExplorerSnapshot_py_offensive_tool_keyword = /ADExplorerSnapshot\.py\.git/ nocase ascii wide
                        $string3_ADExplorerSnapshot_py_offensive_tool_keyword = "import adexpsnapshot" nocase ascii wide

    condition:
        any of them
}