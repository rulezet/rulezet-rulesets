rule rule_CIMplant_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CIMplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CIMplant"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_CIMplant_greyware_tool_keyword = /\%SystemRoot\%\\\\MEMORY\.DMP/ nocase ascii wide
                        $string2_CIMplant_greyware_tool_keyword = /C\:\\Windows\\MEMORY\.DMP/ nocase ascii wide

    condition:
        any of them
}