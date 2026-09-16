rule DCOMPotato
{
    meta:
        description = "Detection patterns for the tool 'DCOMPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DCOMPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DCOMPotato\.git/ nocase ascii wide
                        $string2 = /DCOMPotato\./ nocase ascii wide
                        $string3 = "DCOMPotato-master" nocase ascii wide
                        $string4 = /McpManagementPotato\./ nocase ascii wide
                        $string5 = "PrinterNotifyPotato " nocase ascii wide
                        $string6 = /PrinterNotifyPotato\./ nocase ascii wide
                        $string7 = "zcgonvh/DCOMPotato" nocase ascii wide

    condition:
        any of them
}