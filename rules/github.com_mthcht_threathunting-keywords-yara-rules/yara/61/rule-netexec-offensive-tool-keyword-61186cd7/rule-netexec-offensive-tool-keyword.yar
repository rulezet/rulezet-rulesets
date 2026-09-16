rule rule_Netexec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Netexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Netexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Netexec_offensive_tool_keyword = /C\:\\Windows\\Temp\\[a-zA-Z0-9]{8}.tmp/ nocase ascii wide

    condition:
        any of them
}