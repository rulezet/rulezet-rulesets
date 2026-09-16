rule rule_Passware_Kit_Forensic_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Passware Kit Forensic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Passware Kit Forensic"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Passware_Kit_Forensic_offensive_tool_keyword = /passware\-kit\-forensic\.sls/ nocase ascii wide
                        $string2_Passware_Kit_Forensic_offensive_tool_keyword = /PasswareKitForensic_.{0,1000}_Setup\.dmg/ nocase ascii wide
                        $string3_Passware_Kit_Forensic_offensive_tool_keyword = /PasswareKitForensic_.{0,1000}_Setup\.msi/ nocase ascii wide
                        $string4_Passware_Kit_Forensic_offensive_tool_keyword = /passware\-kit\-forensic\-64bit\.msi/ nocase ascii wide

    condition:
        any of them
}