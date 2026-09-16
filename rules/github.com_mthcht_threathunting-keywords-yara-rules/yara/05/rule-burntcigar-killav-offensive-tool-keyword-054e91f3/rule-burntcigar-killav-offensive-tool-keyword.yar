rule rule_Burntcigar_KillAV_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Burntcigar KillAV' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Burntcigar KillAV"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Burntcigar_KillAV_offensive_tool_keyword = /\/KillAV\.exe/ nocase ascii wide
                        $string2_Burntcigar_KillAV_offensive_tool_keyword = /\\KillAV\.exe/ nocase ascii wide
                        $string3_Burntcigar_KillAV_offensive_tool_keyword = "7010b962fefc8fb879e19b1f170345478875b81748b5a146218a7b0337627060" nocase ascii wide
                        $string4_Burntcigar_KillAV_offensive_tool_keyword = "aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03" nocase ascii wide
                        $string5_Burntcigar_KillAV_offensive_tool_keyword = /WorkNew19\\KillAV\\Release\\KillAV\.pdb/ nocase ascii wide

    condition:
        any of them
}