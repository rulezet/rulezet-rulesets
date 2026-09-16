rule rule_Burntcigar_KillAV_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Burntcigar KillAV' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Burntcigar KillAV"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Burntcigar_KillAV_greyware_tool_keyword = /\\\\\\\\\.\\\\aswSP_Avar/ nocase ascii wide

    condition:
        any of them
}