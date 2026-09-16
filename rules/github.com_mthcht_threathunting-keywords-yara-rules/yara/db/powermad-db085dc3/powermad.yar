rule Powermad
{
    meta:
        description = "Detection patterns for the tool 'Powermad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powermad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Powermad\.git/ nocase ascii wide
                        $string2 = /\\Powermad/ nocase ascii wide
                        $string3 = /Invoke\-DNSUpdate\.ps1/ nocase ascii wide
                        $string4 = /powermad\.ps1/ nocase ascii wide
                        $string5 = /Powermad\.psd1/ nocase ascii wide
                        $string6 = /Powermad\.psm1/ nocase ascii wide
                        $string7 = "Powermad-master" nocase ascii wide

    condition:
        any of them
}