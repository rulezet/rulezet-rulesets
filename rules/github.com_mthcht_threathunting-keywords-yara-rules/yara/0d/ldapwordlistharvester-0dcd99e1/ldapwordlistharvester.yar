rule LDAPWordlistHarvester
{
    meta:
        description = "Detection patterns for the tool 'LDAPWordlistHarvester' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAPWordlistHarvester"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/LDAPWordlistHarvester\.git/ nocase ascii wide
                        $string2 = /LDAPWordlistHarvester\.ps1/ nocase ascii wide
                        $string3 = /LDAPWordlistHarvester\.py/ nocase ascii wide
                        $string4 = "LDAPWordlistHarvester-main" nocase ascii wide
                        $string5 = "p0dalirius/LDAPWordlistHarvester" nocase ascii wide
                        $string6 = "Powershell LDAPWordlistHarvester" nocase ascii wide

    condition:
        any of them
}