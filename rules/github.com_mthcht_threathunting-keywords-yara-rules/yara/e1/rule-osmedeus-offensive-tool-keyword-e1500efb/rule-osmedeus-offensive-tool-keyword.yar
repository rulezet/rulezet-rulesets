rule rule_Osmedeus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Osmedeus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Osmedeus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Osmedeus_offensive_tool_keyword = /\/cloudbrute\.yaml/ nocase ascii wide
                        $string2_Osmedeus_offensive_tool_keyword = "/osmedeus" nocase ascii wide
                        $string3_Osmedeus_offensive_tool_keyword = /\/portscan\.yaml/ nocase ascii wide
                        $string4_Osmedeus_offensive_tool_keyword = /\/spider\.yaml/ nocase ascii wide
                        $string5_Osmedeus_offensive_tool_keyword = /\/subdomain\.yaml/ nocase ascii wide
                        $string6_Osmedeus_offensive_tool_keyword = /\/vulnscan\.yaml/ nocase ascii wide
                        $string7_Osmedeus_offensive_tool_keyword = /\/workflow\/test\/dirbscan\.yaml/ nocase ascii wide
                        $string8_Osmedeus_offensive_tool_keyword = "osmedeus cloud" nocase ascii wide
                        $string9_Osmedeus_offensive_tool_keyword = "osmedeus health" nocase ascii wide
                        $string10_Osmedeus_offensive_tool_keyword = "osmedeus provider" nocase ascii wide
                        $string11_Osmedeus_offensive_tool_keyword = "osmedeus scan" nocase ascii wide
                        $string12_Osmedeus_offensive_tool_keyword = "osmedeus utils" nocase ascii wide
                        $string13_Osmedeus_offensive_tool_keyword = /scan\s\-T\slist_of_targets\.txt/ nocase ascii wide

    condition:
        any of them
}