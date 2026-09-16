rule rule_Amsi_Bypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Amsi_Bypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amsi_Bypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Amsi_Bypass_offensive_tool_keyword = "/Amsi_Bypass_In_2023" nocase ascii wide
                        $string2_Amsi_Bypass_offensive_tool_keyword = /Attack_AmsiOpenSession\.ps1/ nocase ascii wide
                        $string3_Amsi_Bypass_offensive_tool_keyword = /Attack_AmsiScanBuffer\.ps1/ nocase ascii wide

    condition:
        any of them
}