rule ADExplorerSnapshot_py
{
    meta:
        description = "Detection patterns for the tool 'ADExplorerSnapshot.py' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADExplorerSnapshot.py"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /ADExplorerSnapshot\.py/ nocase ascii wide
                        $string2 = /ADExplorerSnapshot\.py\.git/ nocase ascii wide
                        $string3 = "import adexpsnapshot" nocase ascii wide

    condition:
        any of them
}