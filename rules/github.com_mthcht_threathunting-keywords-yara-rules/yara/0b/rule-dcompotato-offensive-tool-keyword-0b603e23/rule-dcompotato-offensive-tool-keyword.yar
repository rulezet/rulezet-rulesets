rule rule_DCOMPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DCOMPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DCOMPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DCOMPotato_offensive_tool_keyword = /\/DCOMPotato\.git/ nocase ascii wide
                        $string2_DCOMPotato_offensive_tool_keyword = /DCOMPotato\./ nocase ascii wide
                        $string3_DCOMPotato_offensive_tool_keyword = "DCOMPotato-master" nocase ascii wide
                        $string4_DCOMPotato_offensive_tool_keyword = /McpManagementPotato\./ nocase ascii wide
                        $string5_DCOMPotato_offensive_tool_keyword = "PrinterNotifyPotato " nocase ascii wide
                        $string6_DCOMPotato_offensive_tool_keyword = /PrinterNotifyPotato\./ nocase ascii wide
                        $string7_DCOMPotato_offensive_tool_keyword = "zcgonvh/DCOMPotato" nocase ascii wide

    condition:
        any of them
}