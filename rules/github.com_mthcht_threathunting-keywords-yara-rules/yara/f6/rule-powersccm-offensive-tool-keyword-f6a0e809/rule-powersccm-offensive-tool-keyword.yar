rule rule_PowerSCCM_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerSCCM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerSCCM_offensive_tool_keyword = /\/PowerSCCM\.git/ nocase ascii wide
                        $string2_PowerSCCM_offensive_tool_keyword = "0ac82760-3e0d-4124-bd1c-92c8dab97171" nocase ascii wide
                        $string3_PowerSCCM_offensive_tool_keyword = /PowerSCCM\.ps1/ nocase ascii wide
                        $string4_PowerSCCM_offensive_tool_keyword = /PowerSCCM\.psd1/ nocase ascii wide
                        $string5_PowerSCCM_offensive_tool_keyword = /PowerSCCM\.psm1/ nocase ascii wide
                        $string6_PowerSCCM_offensive_tool_keyword = "PowerSCCM-master" nocase ascii wide
                        $string7_PowerSCCM_offensive_tool_keyword = "PowerShellMafia/PowerSCCM" nocase ascii wide

    condition:
        any of them
}