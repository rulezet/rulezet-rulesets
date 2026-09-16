rule rule_RID_Hijacking_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RID-Hijacking' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RID-Hijacking"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RID_Hijacking_offensive_tool_keyword = /\srid_hijack\.py/ nocase ascii wide
                        $string2_RID_Hijacking_offensive_tool_keyword = /\/rid_hijack\.py/ nocase ascii wide
                        $string3_RID_Hijacking_offensive_tool_keyword = /\/RID\-Hijacking\.git/ nocase ascii wide
                        $string4_RID_Hijacking_offensive_tool_keyword = /\[\+\]\sElevated\sto\sSYSTEM\sprivileges/ nocase ascii wide
                        $string5_RID_Hijacking_offensive_tool_keyword = /\\persistence\\elevated\\rid_hijack/ nocase ascii wide
                        $string6_RID_Hijacking_offensive_tool_keyword = /\\rid_hijack\.py/ nocase ascii wide
                        $string7_RID_Hijacking_offensive_tool_keyword = /\\rid_hijack\.rb/ nocase ascii wide
                        $string8_RID_Hijacking_offensive_tool_keyword = /\\RID\-Hijacking\\/ nocase ascii wide
                        $string9_RID_Hijacking_offensive_tool_keyword = /\\RID\-Hijacking\-master/ nocase ascii wide
                        $string10_RID_Hijacking_offensive_tool_keyword = "233d785a077c50ad57de73da20e8696258a99edbc6961b92530dac81aede0bcb" nocase ascii wide
                        $string11_RID_Hijacking_offensive_tool_keyword = "9f1853b2b8ee03b428bfcad0502959b2a00761471599e3db4c86ab9550df9b69" nocase ascii wide
                        $string12_RID_Hijacking_offensive_tool_keyword = "a18ad37ac14721d1aab3478bdb2d5534b5035dfb9b3fa5d0945f4d5252936e51" nocase ascii wide
                        $string13_RID_Hijacking_offensive_tool_keyword = "e75d251f639cc70aba21e621c2710dc3ee9dc15d1a677a157f83c14e9aff5f8e" nocase ascii wide
                        $string14_RID_Hijacking_offensive_tool_keyword = "f236aee384d7a0fab7fc186454ee6adb83b756843ecf75ec14b3df826a66ff1d" nocase ascii wide
                        $string15_RID_Hijacking_offensive_tool_keyword = "Invoke-RIDHijacking" nocase ascii wide
                        $string16_RID_Hijacking_offensive_tool_keyword = /invoke\-ridhijacking\.py/ nocase ascii wide
                        $string17_RID_Hijacking_offensive_tool_keyword = "r4wd3r/RID-Hijacking" nocase ascii wide
                        $string18_RID_Hijacking_offensive_tool_keyword = /RIDHIJACK\.ps1/ nocase ascii wide

    condition:
        any of them
}