rule GodPotato
{
    meta:
        description = "Detection patterns for the tool 'GodPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GodPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/GodPotato\.exe/ nocase ascii wide
                        $string2 = /\\GodPotato\.exe/ nocase ascii wide
                        $string3 = ">GodPotato<" nocase ascii wide
                        $string4 = "GodPotatoContext was not initialized" nocase ascii wide
                        $string5 = "ncacn_ip_tcp:fuck you !" nocase ascii wide

    condition:
        any of them
}