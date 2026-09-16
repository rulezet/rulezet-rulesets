rule rule_GodPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GodPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GodPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GodPotato_offensive_tool_keyword = /\/GodPotato\.exe/ nocase ascii wide
                        $string2_GodPotato_offensive_tool_keyword = /\\GodPotato\.exe/ nocase ascii wide
                        $string3_GodPotato_offensive_tool_keyword = ">GodPotato<" nocase ascii wide
                        $string4_GodPotato_offensive_tool_keyword = "GodPotatoContext was not initialized" nocase ascii wide
                        $string5_GodPotato_offensive_tool_keyword = "ncacn_ip_tcp:fuck you !" nocase ascii wide

    condition:
        any of them
}