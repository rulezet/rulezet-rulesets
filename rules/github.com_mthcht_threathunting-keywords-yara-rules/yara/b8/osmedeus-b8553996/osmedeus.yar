rule Osmedeus
{
    meta:
        description = "Detection patterns for the tool 'Osmedeus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Osmedeus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/cloudbrute\.yaml/ nocase ascii wide
                        $string2 = "/osmedeus" nocase ascii wide
                        $string3 = /\/portscan\.yaml/ nocase ascii wide
                        $string4 = /\/spider\.yaml/ nocase ascii wide
                        $string5 = /\/subdomain\.yaml/ nocase ascii wide
                        $string6 = /\/vulnscan\.yaml/ nocase ascii wide
                        $string7 = /\/workflow\/test\/dirbscan\.yaml/ nocase ascii wide
                        $string8 = "osmedeus cloud" nocase ascii wide
                        $string9 = "osmedeus health" nocase ascii wide
                        $string10 = "osmedeus provider" nocase ascii wide
                        $string11 = "osmedeus scan" nocase ascii wide
                        $string12 = "osmedeus utils" nocase ascii wide
                        $string13 = /scan\s\-T\slist_of_targets\.txt/ nocase ascii wide

    condition:
        any of them
}