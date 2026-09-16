rule rule_LDAPWordlistHarvester_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LDAPWordlistHarvester' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAPWordlistHarvester"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LDAPWordlistHarvester_offensive_tool_keyword = /\/LDAPWordlistHarvester\.git/ nocase ascii wide
                        $string2_LDAPWordlistHarvester_offensive_tool_keyword = /LDAPWordlistHarvester\.ps1/ nocase ascii wide
                        $string3_LDAPWordlistHarvester_offensive_tool_keyword = /LDAPWordlistHarvester\.py/ nocase ascii wide
                        $string4_LDAPWordlistHarvester_offensive_tool_keyword = "LDAPWordlistHarvester-main" nocase ascii wide
                        $string5_LDAPWordlistHarvester_offensive_tool_keyword = "p0dalirius/LDAPWordlistHarvester" nocase ascii wide
                        $string6_LDAPWordlistHarvester_offensive_tool_keyword = "Powershell LDAPWordlistHarvester" nocase ascii wide

    condition:
        any of them
}