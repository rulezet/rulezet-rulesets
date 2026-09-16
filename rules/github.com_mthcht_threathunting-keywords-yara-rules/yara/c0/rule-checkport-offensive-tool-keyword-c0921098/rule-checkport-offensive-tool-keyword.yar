rule rule_CheckPort_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CheckPort' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheckPort"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CheckPort_offensive_tool_keyword = /\/CheckPort\.exe/ nocase ascii wide
                        $string2_CheckPort_offensive_tool_keyword = /\\CheckPort\.exe/ nocase ascii wide
                        $string3_CheckPort_offensive_tool_keyword = /\\Release\\CheckPort\.pdb/ nocase ascii wide
                        $string4_CheckPort_offensive_tool_keyword = "'Product'>CheckPort" nocase ascii wide

    condition:
        any of them
}