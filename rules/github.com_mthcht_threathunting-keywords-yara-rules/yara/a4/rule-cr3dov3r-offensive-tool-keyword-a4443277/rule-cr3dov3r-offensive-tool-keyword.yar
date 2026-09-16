rule rule_Cr3dOv3r_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cr3dOv3r' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cr3dOv3r"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Cr3dOv3r_offensive_tool_keyword = "Cr3dOv3r" nocase ascii wide

    condition:
        any of them
}